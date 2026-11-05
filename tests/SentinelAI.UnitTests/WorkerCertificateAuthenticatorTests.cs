using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using SentinelAI.Application;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;

namespace SentinelAI.UnitTests;

public sealed class WorkerCertificateAuthenticatorTests
{
    [Fact]
    public async Task Enrolled_certificate_authenticates_as_the_bound_tenant_and_worker_only()
    {
        using var certificate = CreateCertificate();
        await using var db = CreateDb();
        var tenantId = Guid.NewGuid();
        var worker = new WorkerRegistration(tenantId, "worker-east-01", "1.0", ["web-assessment"]);
        worker.Heartbeat();
        db.Workers.Add(worker);
        db.WorkerClientCertificates.Add(CreateBinding(tenantId, worker.Identity, certificate));
        await db.SaveChangesAsync();

        var principal = await new WorkerCertificateAuthenticator(db).AuthenticateAsync(certificate);

        Assert.NotNull(principal);
        Assert.Equal(tenantId.ToString("D"), principal.FindFirst("tenant_id")?.Value);
        Assert.Equal(worker.Identity, principal.FindFirst("worker_id")?.Value);
        Assert.Equal(nameof(UserRole.Worker), principal.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value);
        Assert.Equal(worker.Id.ToString("D"), principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value);
    }

    [Fact]
    public async Task Unknown_certificate_is_rejected_even_when_the_presented_certificate_is_well_formed()
    {
        using var certificate = CreateCertificate();
        await using var db = CreateDb();

        var principal = await new WorkerCertificateAuthenticator(db).AuthenticateAsync(certificate);

        Assert.Null(principal);
    }

    [Fact]
    public async Task Revoked_certificate_is_rejected_immediately()
    {
        using var certificate = CreateCertificate();
        await using var db = CreateDb();
        var tenantId = Guid.NewGuid();
        var worker = new WorkerRegistration(tenantId, "worker-east-02", "1.0", ["web-assessment"]);
        var binding = CreateBinding(tenantId, worker.Identity, certificate);
        binding.Revoke(Guid.NewGuid(), "Worker host replaced");
        db.Workers.Add(worker);
        db.WorkerClientCertificates.Add(binding);
        await db.SaveChangesAsync();

        var principal = await new WorkerCertificateAuthenticator(db).AuthenticateAsync(certificate);

        Assert.Null(principal);
    }

    [Fact]
    public async Task Expired_binding_is_rejected_even_when_the_certificate_thumbprint_matches()
    {
        using var certificate = CreateCertificate();
        await using var db = CreateDb();
        var tenantId = Guid.NewGuid();
        var worker = new WorkerRegistration(tenantId, "worker-east-03", "1.0", ["web-assessment"]);
        var binding = new WorkerClientCertificate(
            tenantId, worker.Identity, Thumbprint(certificate), certificate.SerialNumber,
            certificate.Subject, certificate.Issuer, DateTimeOffset.UtcNow.AddDays(-100),
            DateTimeOffset.UtcNow.AddDays(-1), Guid.NewGuid());
        db.Workers.Add(worker);
        db.WorkerClientCertificates.Add(binding);
        await db.SaveChangesAsync();

        Assert.Null(await new WorkerCertificateAuthenticator(db).AuthenticateAsync(certificate));
    }

    [Fact]
    public async Task Disabled_worker_cannot_authenticate_with_an_otherwise_valid_certificate()
    {
        using var certificate = CreateCertificate();
        await using var db = CreateDb();
        var tenantId = Guid.NewGuid();
        var worker = new WorkerRegistration(tenantId, "worker-east-04", "1.0", ["web-assessment"]);
        worker.Disable();
        db.Workers.Add(worker);
        db.WorkerClientCertificates.Add(CreateBinding(tenantId, worker.Identity, certificate));
        await db.SaveChangesAsync();

        Assert.Null(await new WorkerCertificateAuthenticator(db).AuthenticateAsync(certificate));
    }

    private static AppDbContext CreateDb()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase($"worker-cert-auth-{Guid.NewGuid():N}")
            .Options;
        return new AppDbContext(options);
    }

    private static WorkerClientCertificate CreateBinding(Guid tenantId, string workerIdentity, X509Certificate2 certificate)
        => new(tenantId, workerIdentity, Thumbprint(certificate), certificate.SerialNumber,
            certificate.Subject, certificate.Issuer,
            new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
            new DateTimeOffset(certificate.NotAfter.ToUniversalTime()), Guid.NewGuid());

    private static string Thumbprint(X509Certificate2 certificate)
        => Convert.ToHexString(SHA256.HashData(certificate.RawData));

    private static X509Certificate2 CreateCertificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=worker-test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var usages = new OidCollection { new("1.3.6.1.5.5.7.3.2") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(10));
    }
}
