namespace SentinelAI.Domain;

public sealed class WorkerClientCertificate
{
    private WorkerClientCertificate() { }

    public WorkerClientCertificate(
        Guid tenantId,
        string workerIdentity,
        string thumbprint,
        string serialNumber,
        string subject,
        string issuer,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        Guid enrolledBy)
    {
        if (tenantId == Guid.Empty) throw new ArgumentException("A tenant is required.", nameof(tenantId));
        if (string.IsNullOrWhiteSpace(workerIdentity)) throw new ArgumentException("A worker identity is required.", nameof(workerIdentity));
        if (string.IsNullOrWhiteSpace(thumbprint) || thumbprint.Length != 64 || thumbprint.Any(character => !Uri.IsHexDigit(character)))
            throw new ArgumentException("A SHA-256 certificate thumbprint is required.", nameof(thumbprint));
        if (notAfter <= notBefore) throw new ArgumentException("Certificate validity period is invalid.", nameof(notAfter));
        if (enrolledBy == Guid.Empty) throw new ArgumentException("The enrolling administrator is required.", nameof(enrolledBy));

        Id = Guid.NewGuid();
        TenantId = tenantId;
        WorkerIdentity = workerIdentity.Trim();
        ThumbprintSha256 = thumbprint.ToUpperInvariant();
        SerialNumber = serialNumber.Trim();
        Subject = subject.Trim();
        Issuer = issuer.Trim();
        NotBefore = notBefore.ToUniversalTime();
        NotAfter = notAfter.ToUniversalTime();
        EnrolledBy = enrolledBy;
        EnrolledAt = DateTimeOffset.UtcNow;
    }

    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public string WorkerIdentity { get; private set; } = string.Empty;
    public string ThumbprintSha256 { get; private set; } = string.Empty;
    public string SerialNumber { get; private set; } = string.Empty;
    public string Subject { get; private set; } = string.Empty;
    public string Issuer { get; private set; } = string.Empty;
    public DateTimeOffset NotBefore { get; private set; }
    public DateTimeOffset NotAfter { get; private set; }
    public Guid EnrolledBy { get; private set; }
    public DateTimeOffset EnrolledAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }
    public Guid? RevokedBy { get; private set; }
    public string? RevocationReason { get; private set; }

    public bool IsActiveAt(DateTimeOffset now)
        => RevokedAt is null && NotBefore <= now && NotAfter > now;

    public void Revoke(Guid administratorId, string reason, DateTimeOffset? revokedAt = null)
    {
        if (RevokedAt is not null) return;
        if (administratorId == Guid.Empty) throw new ArgumentException("A revoking administrator is required.", nameof(administratorId));
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length > 500)
            throw new ArgumentException("A bounded revocation reason is required.", nameof(reason));
        RevokedAt = (revokedAt ?? DateTimeOffset.UtcNow).ToUniversalTime();
        RevokedBy = administratorId;
        RevocationReason = reason.Trim();
    }
}
