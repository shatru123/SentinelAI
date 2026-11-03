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
    string? PrivateWorkerIdentity = null,
    IReadOnlyCollection<string>? PrivateNetworkRanges = null,
    int MaxTotalRequests = 200,
    int MaxConcurrentRequests = 4,
    int MaxPages = 24,
    int MaxCrawlDepth = 2,
    int MaxResponseBytes = 512 * 1024);

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
    IReadOnlyCollection<Guid>? PublicTargetAuthorizationIds = null,
    IReadOnlyCollection<string>? PrivateNetworkRanges = null,
    int MaxTotalRequests = 200,
    int MaxConcurrentRequests = 4,
    int MaxPages = 24,
    int MaxCrawlDepth = 2,
    int MaxResponseBytes = 512 * 1024);
public sealed record WebAssessmentResponse(Guid Id, Guid JobId, Guid ScopeId, string TargetUrl, string Profile,
    WebHostingMode HostingMode, WebAssessmentStatus Status, ScanJobStatus JobStatus, DateTimeOffset CreatedAt,
    DateTimeOffset? StartedAt, DateTimeOffset? CompletedAt, int DiscoveredEndpointCount, string? ReportStorageKey);
public sealed record WebAssessmentEndpointResponse(Guid Id, string Url, string Method, int Depth, string Kind, DateTimeOffset DiscoveredAt);
public sealed record WebAssessmentFindingResponse(Guid Id, string Title, FindingSeverity Severity, string? Category, string? Confidence,
    string? AffectedUrl, string? HttpMethod, string? Parameter, string? Description, string? Impact, string? Reproduction,
    string? Remediation, WebCheckStatus CheckStatus, DateTimeOffset CreatedAt);
public sealed record EvidenceResponse(Guid Id, Guid FindingId, string Source, string Summary, string Sha256, string? RedactedContent, string? ContentType, DateTimeOffset CollectedAt);
public sealed record ScreenshotResponse(Guid Id, string Url, string ScreenshotType, string Format, string Sha256, DateTimeOffset CapturedAt);
public sealed record WebAssessmentCheckResponse(Guid Id, string CheckId, string Name, string Category, WebCheckStatus Status, DateTimeOffset StartedAt, DateTimeOffset? CompletedAt, string? AffectedEndpoint, string? Reason);
public sealed record AgentResponse(Guid Id, string Name, string Status, DateTimeOffset LastHeartbeatAt);
public sealed record WorkerRegistrationRequest(string Identity, string Version, IReadOnlyCollection<string> Capabilities, int Capacity = 1);
public sealed record WorkerHeartbeatRequest(string Identity, int ActiveJobs, int Capacity, DateTimeOffset? LastJobStartedAt = null, DateTimeOffset? LastJobCompletedAt = null);
public sealed record WorkerResponse(Guid Id, string Identity, string Version, WorkerStatus Status, IReadOnlyCollection<string> Capabilities, DateTimeOffset LastHeartbeatAt,
    int CurrentActiveJobs = 0, int MaximumCapacity = 1, DateTimeOffset? LastJobStartedAt = null, DateTimeOffset? LastJobCompletedAt = null,
    bool PrivateAssessmentApproved = false, IReadOnlyCollection<string>? ApprovedPrivateNetworkRanges = null);
public sealed record PublicTargetAuthorizationRequest(string Target, string Reason);
public sealed record PublicTargetAuthorizationApprovalRequest(string Evidence, string Method, DateTimeOffset ExpiresAt);
public sealed record PublicTargetAuthorizationResponse(Guid Id, string Target, PublicTargetAuthorizationStatus Status, Guid RequestedBy, Guid? ApprovedBy, DateTimeOffset CreatedAt, DateTimeOffset? ApprovedAt, DateTimeOffset? ExpiresAt);
public sealed record PrivateWorkerAuthorizationRequest(IReadOnlyCollection<string> NetworkRanges, bool Enabled = true);
public sealed record WorkerProvisionRequest(string Version, IReadOnlyCollection<string> Capabilities, IReadOnlyCollection<string>? PrivateNetworkRanges = null);
public sealed record PagedResponse<T>(IReadOnlyCollection<T> Items, int Page, int PageSize, int TotalCount);

public sealed record CurrentUserResponse(string Subject, Guid TenantId, Guid UserId, string Role);

public sealed record DashboardSummaryResponse(
    int AssetsObserved,
    int ReachabilityConfirmedAssets,
    int ObservedServices,
    int TotalFindings,
    int CriticalFindings,
    int HighFindings,
    int MediumFindings,
    int LowFindings,
    int InfoFindings,
    int ActiveAssessments,
    int RunningJobs,
    int TotalJobs,
    int HealthyWorkers,
    int TotalWorkers,
    IReadOnlyCollection<WebAssessmentResponse> RecentAssessments,
    IReadOnlyCollection<ScanJobSummaryResponse> RecentScans,
    IReadOnlyCollection<MonitoringEventResponse> RecentEvents,
    int QueuedJobs = 0,
    int CompletedJobs = 0);

public sealed record ScanJobSummaryResponse(
    Guid Id,
    Guid ScopeId,
    string ScopeName,
    string OperationProfile,
    ScanJobStatus Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset? StartedAt,
    DateTimeOffset? CompletedAt,
    string? AssignedWorkerIdentity,
    DateTimeOffset ExpiresAt,
    string? FailureReason = null);

public sealed record MonitoringEventResponse(
    Guid Id,
    Guid TenantId,
    string Action,
    string ResourceType,
    Guid? ResourceId,
    Guid? ActorId,
    DateTimeOffset OccurredAt,
    string? Detail);

public sealed record FindingDetailResponse(
    Guid Id,
    string Title,
    FindingSeverity Severity,
    Guid? AssetId,
    Guid? WebAssessmentId,
    string? TargetUrl,
    string? Category,
    string? Confidence,
    string? AffectedUrl,
    string? HttpMethod,
    string? Parameter,
    string? Description,
    string? Impact,
    string? Reproduction,
    string? Remediation,
    WebCheckStatus? CheckStatus,
    DateTimeOffset CreatedAt,
    IReadOnlyCollection<EvidenceResponse> Evidence,
    IReadOnlyCollection<ScreenshotResponse> Screenshots);


public sealed record SyncEpssRequest(IReadOnlyCollection<string> CveIds);

public sealed record CreateSoftwareComponentRequest(
    string Vendor,
    string Product,
    string? Version,
    string CpeName,
    string IdentificationMethod,
    Guid EvidenceId,
    decimal Confidence);

public sealed record ConfirmSoftwareComponentRequest(Guid EvidenceId, decimal Confidence);

public sealed record SoftwareComponentResponse(
    Guid Id,
    Guid AssetId,
    string Vendor,
    string Product,
    string? Version,
    string CpeName,
    string IdentificationMethod,
    Guid EvidenceId,
    decimal Confidence,
    bool IsOperatorConfirmed,
    DateTimeOffset FirstObservedAt,
    DateTimeOffset LastObservedAt);

public sealed record AssetVulnerabilityMatchResponse(
    Guid Id,
    Guid AssetId,
    Guid SoftwareComponentId,
    string CveId,
    VulnerabilityMatchStatus Status,
    string Explanation,
    string? CriteriaId,
    DateTimeOffset FirstObservedAt,
    DateTimeOffset LastObservedAt);

public sealed record VulnerabilityCvssResponse(
    string Version,
    string Vector,
    decimal BaseScore,
    string Severity,
    string Source,
    DateTimeOffset ObservedAt);

public sealed record VulnerabilityEpssResponse(
    decimal Score,
    decimal Percentile,
    DateOnly AsOfDate,
    DateTimeOffset ImportedAt);

public sealed record VulnerabilityKevResponse(
    bool IsListed,
    string CatalogVersion,
    DateTimeOffset CatalogReleasedAt,
    string VendorProject,
    string Product,
    DateOnly DateAdded,
    DateOnly DueDate,
    string RequiredAction,
    bool? KnownRansomwareCampaignUse);

public sealed record VulnerabilityCatalogResponse(
    string CveId,
    string Status,
    DateTimeOffset PublishedAt,
    DateTimeOffset LastModifiedAt,
    string Description,
    IReadOnlyCollection<string> CweIds,
    IReadOnlyCollection<string> References,
    IReadOnlyCollection<VulnerabilityCvssResponse> Cvss,
    VulnerabilityEpssResponse? Epss,
    VulnerabilityKevResponse? Kev);

public sealed record VulnerabilityCatalogListItem(
    string CveId,
    string Status,
    DateTimeOffset PublishedAt,
    DateTimeOffset LastModifiedAt,
    string Description);

public sealed record VulnerabilitySyncResponse(int RecordsProcessed);


public sealed record AssessVulnerabilityRiskRequest(bool IsInternetFacing, bool IsBusinessCritical);

public sealed record VulnerabilityTriageAssessmentResponse(
    Guid Id,
    Guid MatchId,
    VulnerabilityRiskPriority Priority,
    decimal? CvssBaseScore,
    string? CvssVersion,
    string? CvssVector,
    DateTimeOffset? CvssObservedAt,
    decimal? EpssScore,
    decimal? EpssPercentile,
    DateOnly? EpssAsOfDate,
    bool IsKnownExploited,
    string? KevCatalogVersion,
    DateTimeOffset? KevCatalogReleasedAt,
    bool IsInternetFacing,
    bool IsBusinessCritical,
    IReadOnlyCollection<string> Reasons,
    string Disclaimer,
    DateTimeOffset AssessedAt);

public sealed record TransitionVulnerabilityMatchRequest(VulnerabilityLifecycleStatus Status, string Reason);

public sealed record VulnerabilityMatchTransitionResponse(
    Guid Id,
    Guid MatchId,
    VulnerabilityLifecycleStatus FromStatus,
    VulnerabilityLifecycleStatus ToStatus,
    Guid ActorId,
    string Reason,
    DateTimeOffset OccurredAt);
