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
    bool PublicTargetOwnershipVerified = false);

public sealed record ScopeResponse(Guid Id, string Name, Guid TenantId, IReadOnlyCollection<TargetDefinition> Targets,
    IReadOnlyCollection<string> ApprovedOperationProfiles, DateTimeOffset ExpiresAt, bool IsActive);

public sealed record CreateScanRequest(Guid ScopeId, string OperationProfile);
public sealed record ScanResponse(Guid Id, Guid ScopeId, ScanJobStatus Status, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, string OperationProfile);
public sealed record AssetResponse(Guid Id, string Address, TargetKind Kind, bool IsOnline, DateTimeOffset LastSeenAt);
public sealed record FindingResponse(Guid Id, string Title, FindingSeverity Severity, Guid? AssetId, DateTimeOffset CreatedAt);
public sealed record AgentResponse(Guid Id, string Name, string Status, DateTimeOffset LastHeartbeatAt);
public sealed record PagedResponse<T>(IReadOnlyCollection<T> Items, int Page, int PageSize, int TotalCount);

public sealed record CurrentUserResponse(string Subject, Guid TenantId, Guid UserId, string Role);
