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
    bool AllowSubdomains = false,
    WebHostingMode? HostingMode = null,
    string? PrivateWorkerIdentity = null);

public sealed record PublicTargetVerificationRequest(string Target, string Evidence, string Verifier, string Method, DateTimeOffset VerifiedAt);

public sealed record ScopeResponse(Guid Id, string Name, Guid TenantId, IReadOnlyCollection<TargetDefinition> Targets,
    IReadOnlyCollection<string> ApprovedOperationProfiles, DateTimeOffset ExpiresAt, bool IsActive,
    WebHostingMode? HostingMode = null, string? PrivateWorkerIdentity = null);

public sealed record CreateScanRequest(Guid ScopeId, string OperationProfile);
public sealed record ScanResponse(Guid Id, Guid ScopeId, ScanJobStatus Status, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, string OperationProfile);
public sealed record AssetResponse(Guid Id, string Address, TargetKind Kind, bool IsOnline, DateTimeOffset LastObservedAt, DateTimeOffset? LastSuccessfulReachabilityAt)
{
    [System.Text.Json.Serialization.JsonPropertyName("lastSeenAt")]
    [Obsolete("Use LastObservedAt or LastSuccessfulReachabilityAt.")]
    public DateTimeOffset LastSeenAt => LastObservedAt;
}
public sealed record AssetServiceResponse(Guid Id, Guid AssetId, string Protocol, int Port, string? Name, string? Version, DateTimeOffset ObservedAt);
public sealed record FindingResponse(Guid Id, string Title, FindingSeverity Severity, Guid? AssetId, DateTimeOffset CreatedAt);
public sealed record CreateWebAssessmentRequest(
    string Name,
    string TargetUrl,
    WebHostingMode HostingMode,
    string? PrivateWorkerIdentity,
    string OperationProfile,
    IReadOnlyCollection<string>? Exclusions,
    int RequestsPerMinute,
    int MaxExecutionSeconds,
    string AuthorizationEvidence,
    DateTimeOffset ExpiresAt,
    bool AllowSubdomains = false,
    IReadOnlyCollection<Guid>? PublicTargetAuthorizationIds = null);
public sealed record WebAssessmentResponse(Guid Id, Guid JobId, Guid ScopeId, string TargetUrl, string Profile,
    WebHostingMode HostingMode, WebAssessmentStatus Status, ScanJobStatus JobStatus, DateTimeOffset CreatedAt,
    DateTimeOffset? StartedAt, DateTimeOffset? CompletedAt, int DiscoveredEndpointCount, string? ReportStorageKey);
public sealed record WebAssessmentEndpointResponse(Guid Id, string Url, string Method, int Depth, string Kind, DateTimeOffset DiscoveredAt);
public sealed record WebAssessmentFindingResponse(Guid Id, string Title, FindingSeverity Severity, string? Category, string? Confidence,
    string? AffectedUrl, string? HttpMethod, string? Parameter, string? Description, string? Impact, string? Reproduction,
    string? Remediation, WebCheckStatus CheckStatus, DateTimeOffset CreatedAt);
public sealed record EvidenceResponse(Guid Id, Guid FindingId, string Source, string Summary, string Sha256, string? RedactedContent, string? ContentType, DateTimeOffset CollectedAt);
public sealed record ScreenshotResponse(Guid Id, string Url, string ScreenshotType, string Format, string Sha256, DateTimeOffset CapturedAt);
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
