namespace SentinelAI.Contracts;

public sealed record EnrollWorkerCertificateRequest(string CertificatePem, IReadOnlyCollection<string>? IntermediateCertificatesPem = null);
public sealed record RevokeWorkerCertificateRequest(string Reason);

public sealed record WorkerClientCertificateResponse(
    Guid Id,
    string WorkerIdentity,
    string ThumbprintSha256,
    string SerialNumber,
    string Subject,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    Guid EnrolledBy,
    DateTimeOffset EnrolledAt,
    DateTimeOffset? RevokedAt,
    Guid? RevokedBy,
    string? RevocationReason);
