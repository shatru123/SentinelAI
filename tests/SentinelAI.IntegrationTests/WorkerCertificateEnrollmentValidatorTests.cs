using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SentinelAI.Api;

namespace SentinelAI.IntegrationTests;

public sealed class WorkerCertificateEnrollmentValidatorTests
{
    [Fact]
    public void Accepts_current_ca_signed_worker_client_certificate_with_matching_subject()
    {
        using var authority = CreateAuthority();
        var rootPath = WriteRoot(authority);
        try
        {
            using var leaf = CreateLeaf(authority, "worker-a", DateTimeOffset.UtcNow.AddMinutes(-2), DateTimeOffset.UtcNow.AddDays(30));
            using var validated = WorkerCertificateEnrollmentValidator.Validate(
                Pem(leaf), [], "worker-a", rootPath);

            Assert.False(validated.HasPrivateKey);
            Assert.Equal("worker-a", validated.GetNameInfo(X509NameType.SimpleName, false));
        }
        finally { File.Delete(rootPath); }
    }

    [Fact]
    public void Rejects_private_key_material_in_enrollment_payload()
    {
        using var authority = CreateAuthority();
        var rootPath = WriteRoot(authority);
        try
        {
            using var leaf = CreateSelfSignedWorker("worker-a");
            var payload = Pem(leaf) + GetRSAPrivateKeyPemOrThrow(leaf);
            Assert.Throws<ArgumentException>(() =>
                WorkerCertificateEnrollmentValidator.Validate(payload, [], "worker-a", rootPath));
        }
        finally { File.Delete(rootPath); }
    }

    [Fact]
    public void Rejects_certificate_signed_by_an_untrusted_ca()
    {
        using var trustedAuthority = CreateAuthority();
        using var otherAuthority = CreateAuthority();
        var rootPath = WriteRoot(trustedAuthority);
        try
        {
            using var leaf = CreateLeaf(otherAuthority, "worker-a", DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(30));
            Assert.Throws<ArgumentException>(() =>
                WorkerCertificateEnrollmentValidator.Validate(Pem(leaf), [], "worker-a", rootPath));
        }
        finally { File.Delete(rootPath); }
    }

    [Fact]
    public void Rejects_certificate_subject_that_does_not_match_administrator_selected_worker()
    {
        using var authority = CreateAuthority();
        var rootPath = WriteRoot(authority);
        try
        {
            using var leaf = CreateLeaf(authority, "worker-b", DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(30));
            Assert.Throws<ArgumentException>(() =>
                WorkerCertificateEnrollmentValidator.Validate(Pem(leaf), [], "worker-a", rootPath));
        }
        finally { File.Delete(rootPath); }
    }

    [Fact]
    public void Rejects_not_yet_valid_certificate()
    {
        using var authority = CreateAuthority();
        var rootPath = WriteRoot(authority);
        try
        {
            var now = DateTimeOffset.UtcNow;
            using var leaf = CreateLeaf(authority, "worker-a", now.AddMinutes(5), now.AddDays(30));
            Assert.Throws<ArgumentException>(() =>
                WorkerCertificateEnrollmentValidator.Validate(Pem(leaf), [], "worker-a", rootPath, now));
        }
        finally { File.Delete(rootPath); }
    }

    [Fact]
    public void Rejects_expired_worker_certificate()
    {
        using var authority = CreateAuthority();
        var rootPath = WriteRoot(authority);
        try
        {
            var now = DateTimeOffset.UtcNow;
            using var leaf = CreateLeaf(authority, "worker-a", now.AddDays(-30), now.AddDays(-1));
            Assert.Throws<ArgumentException>(() =>
                WorkerCertificateEnrollmentValidator.Validate(Pem(leaf), [], "worker-a", rootPath, now));
        }
        finally { File.Delete(rootPath); }
    }

    [Fact]
    public void Rejects_certificate_lifetime_longer_than_ninety_days()
    {
        using var authority = CreateAuthority();
        var rootPath = WriteRoot(authority);
        try
        {
            var now = DateTimeOffset.UtcNow;
            using var leaf = CreateLeaf(authority, "worker-a", now.AddMinutes(-1), now.AddDays(91));
            Assert.Throws<ArgumentException>(() =>
                WorkerCertificateEnrollmentValidator.Validate(Pem(leaf), [], "worker-a", rootPath, now));
        }
        finally { File.Delete(rootPath); }
    }

    [Fact]
    public void Rejects_certificate_without_client_authentication_eku()
    {
        using var authority = CreateAuthority();
        var rootPath = WriteRoot(authority);
        try
        {
            using var leaf = CreateLeaf(authority, "worker-a", DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(30), clientAuthentication: false);
            Assert.Throws<ArgumentException>(() =>
                WorkerCertificateEnrollmentValidator.Validate(Pem(leaf), [], "worker-a", rootPath));
        }
        finally { File.Delete(rootPath); }
    }

    [Fact]
    public void Rejects_intermediate_certificate_with_private_key()
    {
        using var authority = CreateAuthority();
        var rootPath = WriteRoot(authority);
        try
        {
            using var leaf = CreateLeaf(authority, "worker-a", DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(30));
            using var intermediate = CreateSelfSignedWorker("intermediate");
            Assert.Throws<ArgumentException>(() =>
                WorkerCertificateEnrollmentValidator.Validate(Pem(leaf), [Pem(intermediate) + GetRSAPrivateKeyPemOrThrow(intermediate)], "worker-a", rootPath));
        }
        finally { File.Delete(rootPath); }
    }

    private static X509Certificate2 CreateAuthority()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=SentinelAI Test Worker CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(365));
    }

    private static X509Certificate2 CreateLeaf(
        X509Certificate2 authority,
        string identity,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        bool clientAuthentication = true)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={identity}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var usages = new OidCollection
        {
            new(clientAuthentication ? WorkerCertificateEnrollmentValidator.ClientAuthenticationEku : "1.3.6.1.5.5.7.3.1")
        };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
        return request.Create(authority, notBefore, notAfter, RandomNumberGenerator.GetBytes(16));
    }

    private static X509Certificate2 CreateSelfSignedWorker(string identity)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={identity}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new(WorkerCertificateEnrollmentValidator.ClientAuthenticationEku) }, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private static string WriteRoot(X509Certificate2 authority)
    {
        var path = Path.Combine(Path.GetTempPath(), $"sentinelai-worker-ca-{Guid.NewGuid():N}.cer");
        File.WriteAllBytes(path, authority.Export(X509ContentType.Cert));
        return path;
    }

    private static string Pem(X509Certificate2 certificate)
        => PemEncoding.WriteString("CERTIFICATE", certificate.RawData);

    private static string GetRSAPrivateKeyPemOrThrow(X509Certificate2 certificate)
    {
        using var privateKey = certificate.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("Expected an RSA private key in the test certificate.");
        return PemEncoding.WriteString("PRIVATE KEY", privateKey.ExportPkcs8PrivateKey());
    }
}
