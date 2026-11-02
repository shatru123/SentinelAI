using SentinelAI.Domain;

namespace SentinelAI.Contracts;

public sealed record CreateScopeRequest(
    string Name,
    IReadOnlyCollection<TargetDefinition> Targets,
    IReadOnlyCollection<string>? Exclusions,
    IReadOnlyCollection<string> ApprovedOperationProfiles,
    int RequestsPerMinute,
    int MaxExecutionSeconds,
    string AuthorizationEvidence,
    DateTimeOffset ExpiresAt,
    bool PublicTargetOwnershipVerified = false,
    IReadOnlyCollection<PublicTargetVerificationRequest>? PublicTargetAuthorizations = null,
    IReadOnlyCollection<Guid>? PublicTargetAuthorizationIds = null,
    bool AllowSubdomains = false);

public sealed record PublicTargetVerificationRequest(string Target, string Evidence, string Verifier, string Method, DateTimeOffset VerifiedAt);

public sealed record ScopeResponse(Guid Id, string Name, Guid TenantId, IReadOnlyCollection<TargetDefinition> Targets,
    IReadOnlyCollection<string> ApprovedOperationProfiles, DateTimeOffset ExpiresAt, bool IsActive);

public sealed record CreateScanRequest(Guid ScopeId, string OperationProfile);
public sealed record ScanResponse(Guid Id, Guid ScopeId, ScanJobStatus Status, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, string OperationProfile);
public sealed record AssetResponse(Guid Id, string Address, TargetKind Kind, bool IsOnline, DateTimeOffset LastSeenAt);
public sealed record FindingResponse(Guid Id, string Title, FindingSeverity Severity, Guid? AssetId, DateTimeOffset CreatedAt);
public sealed record AgentResponse(Guid Id, string Name, string Status, DateTimeOffset LastHeartbeatAt);
public sealed record WorkerRegistrationRequest(string Identity, string Version, IReadOnlyCollection<string> Capabilities, int Capacity = 1);
public sealed record WorkerHeartbeatRequest(string Identity, int ActiveJobs, int Capacity, DateTimeOffset? LastJobStartedAt = null, DateTimeOffset? LastJobCompletedAt = null);
public sealed record WorkerResponse(Guid Id, string Identity, string Version, WorkerStatus Status, IReadOnlyCollection<string> Capabilities, DateTimeOffset LastHeartbeatAt,
    int CurrentActiveJobs = 0, int MaximumCapacity = 1, DateTimeOffset? LastJobStartedAt = null, DateTimeOffset? LastJobCompletedAt = null);
public sealed record PublicTargetAuthorizationRequest(string Target, string Reason);
public sealed record PublicTargetAuthorizationApprovalRequest(string Evidence, string Method, DateTimeOffset ExpiresAt);
public sealed record PublicTargetAuthorizationResponse(Guid Id, string Target, PublicTargetAuthorizationStatus Status, Guid RequestedBy, Guid? ApprovedBy, DateTimeOffset CreatedAt, DateTimeOffset? ApprovedAt, DateTimeOffset? ExpiresAt);
public sealed record PagedResponse<T>(IReadOnlyCollection<T> Items, int Page, int PageSize, int TotalCount);

public sealed record CurrentUserResponse(string Subject, Guid TenantId, Guid UserId, string Role);
