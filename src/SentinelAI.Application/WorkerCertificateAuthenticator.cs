using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain;

namespace SentinelAI.Application;

public sealed class WorkerCertificateAuthenticator(IAppDbContext db)
{
    public async Task<ClaimsPrincipal?> AuthenticateAsync(
        X509Certificate2 certificate,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var thumbprint = Convert.ToHexString(SHA256.HashData(certificate.RawData));
        var now = DateTimeOffset.UtcNow;

        var binding = await db.WorkerClientCertificates.AsNoTracking()
            .SingleOrDefaultAsync(item => item.ThumbprintSha256 == thumbprint, cancellationToken);
        if (binding is null || !binding.IsActiveAt(now))
            return null;

        var worker = await db.Workers.AsNoTracking().SingleOrDefaultAsync(
            item => item.TenantId == binding.TenantId && item.Identity == binding.WorkerIdentity,
            cancellationToken);
        if (worker is null || worker.Status == WorkerStatus.Disabled)
            return null;

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, worker.Id.ToString("D")),
            new Claim(ClaimTypes.Name, worker.Identity),
            new Claim("tenant_id", worker.TenantId.ToString("D")),
            new Claim(ClaimTypes.Role, nameof(UserRole.Worker)),
            new Claim("worker_id", worker.Identity)
        };
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "WorkerCertificate"));
    }
}
