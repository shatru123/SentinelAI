using System.Text.Json.Serialization;

namespace SentinelAI.Domain;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum TargetKind { Network, Web, Code }
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ScanJobStatus { Queued, Running, Completed, Failed, Cancelled, Expired }
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum FindingSeverity { Informational, Low, Medium, High, Critical }
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AgentExecutionStatus { Pending, Running, Completed, Failed, Cancelled }
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum UserRole { Admin, SecurityAnalyst, Viewer, Worker }

public sealed class Tenant
{
    private Tenant() { }
    public Tenant(string name) { Id = Guid.NewGuid(); Name = name; CreatedAt = DateTimeOffset.UtcNow; }
    public Guid Id { get; private set; }
    public string Name { get; private set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; private set; }
    public byte[] RowVersion { get; private set; } = Guid.NewGuid().ToByteArray();
}

public sealed class User
{
    private User() { }
    public User(Guid tenantId, string subject, string displayName, UserRole role)
    { Id = Guid.NewGuid(); TenantId = tenantId; Subject = subject; DisplayName = displayName; Role = role; CreatedAt = DateTimeOffset.UtcNow; }
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public string Subject { get; private set; } = string.Empty;
    public string DisplayName { get; private set; } = string.Empty;
    public UserRole Role { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
}

public sealed class TargetScope
{
    private TargetScope() { }
    public TargetScope(Guid tenantId, string name, Guid createdBy, DateTimeOffset expiresAt)
    { Id = Guid.NewGuid(); TenantId = tenantId; Name = name; CreatedBy = createdBy; CreatedAt = DateTimeOffset.UtcNow; ExpiresAt = expiresAt; }
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public string Name { get; private set; } = string.Empty;
    public List<TargetDefinition> Targets { get; private set; } = [];
    public List<string> Exclusions { get; private set; } = [];
    public List<string> ApprovedOperationProfiles { get; private set; } = [];
    public int RequestsPerMinute { get; private set; } = 30;
    public int MaxExecutionSeconds { get; private set; } = 300;
    public string AuthorizationEvidence { get; private set; } = string.Empty;
    public bool PublicTargetOwnershipVerified { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }
    public Guid CreatedBy { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public bool IsActive => ExpiresAt > DateTimeOffset.UtcNow;
    public byte[] RowVersion { get; private set; } = Guid.NewGuid().ToByteArray();

    public void Configure(IReadOnlyCollection<TargetDefinition> targets, IReadOnlyCollection<string> exclusions,
        IReadOnlyCollection<string> profiles, int requestsPerMinute, int maxExecutionSeconds,
        string authorizationEvidence, bool publicTargetOwnershipVerified)
    {
        Targets = targets.ToList(); Exclusions = exclusions.ToList(); ApprovedOperationProfiles = profiles.ToList();
        RequestsPerMinute = requestsPerMinute; MaxExecutionSeconds = maxExecutionSeconds;
        AuthorizationEvidence = authorizationEvidence; PublicTargetOwnershipVerified = publicTargetOwnershipVerified;
    }
}

public sealed record TargetDefinition(TargetKind Kind, string Value);

public sealed class ScanPolicy
{
    private ScanPolicy() { }
    public ScanPolicy(Guid tenantId, string name, bool intrusiveChecksRequireApproval = true)
    { Id = Guid.NewGuid(); TenantId = tenantId; Name = name; IntrusiveChecksRequireApproval = intrusiveChecksRequireApproval; CreatedAt = DateTimeOffset.UtcNow; }
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public string Name { get; private set; } = string.Empty;
    public bool IntrusiveChecksRequireApproval { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
}

public sealed class AgentJob
{
    private AgentJob() { }
    public AgentJob(Guid tenantId, Guid scopeId, Guid requestedBy, string operationProfile)
    { Id = Guid.NewGuid(); TenantId = tenantId; ScopeId = scopeId; RequestedBy = requestedBy; OperationProfile = operationProfile; Status = ScanJobStatus.Queued; CreatedAt = DateTimeOffset.UtcNow; ExpiresAt = CreatedAt.AddMinutes(15); }
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid ScopeId { get; private set; }
    public Guid RequestedBy { get; private set; }
    public string OperationProfile { get; private set; } = string.Empty;
    public ScanJobStatus Status { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? StartedAt { get; private set; }
    public DateTimeOffset? CompletedAt { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }
    public string? FailureReason { get; private set; }
    public byte[] RowVersion { get; private set; } = Guid.NewGuid().ToByteArray();
    public void Start() { if (Status != ScanJobStatus.Queued) throw new InvalidOperationException("Only queued jobs can start."); Status = ScanJobStatus.Running; StartedAt = DateTimeOffset.UtcNow; }
    public void Complete() { if (Status != ScanJobStatus.Running) throw new InvalidOperationException("Only running jobs can complete."); Status = ScanJobStatus.Completed; CompletedAt = DateTimeOffset.UtcNow; }
    public void Fail(string reason) { Status = ScanJobStatus.Failed; FailureReason = reason; CompletedAt = DateTimeOffset.UtcNow; }
    public void Cancel() { if (Status is ScanJobStatus.Completed or ScanJobStatus.Failed or ScanJobStatus.Cancelled) return; Status = ScanJobStatus.Cancelled; CompletedAt = DateTimeOffset.UtcNow; }
    public void Expire() { if (Status is ScanJobStatus.Queued or ScanJobStatus.Running) { Status = ScanJobStatus.Expired; CompletedAt = DateTimeOffset.UtcNow; } }
}

public sealed class AgentExecution
{
    private AgentExecution() { }
    public AgentExecution(Guid jobId, string agentName) { Id = Guid.NewGuid(); AgentJobId = jobId; AgentName = agentName; Status = AgentExecutionStatus.Pending; CreatedAt = DateTimeOffset.UtcNow; }
    public Guid Id { get; private set; }
    public Guid AgentJobId { get; private set; }
    public string AgentName { get; private set; } = string.Empty;
    public AgentExecutionStatus Status { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? StartedAt { get; private set; }
    public DateTimeOffset? CompletedAt { get; private set; }
    public string? Error { get; private set; }
    public void Start() { Status = AgentExecutionStatus.Running; StartedAt = DateTimeOffset.UtcNow; }
    public void Complete() { Status = AgentExecutionStatus.Completed; CompletedAt = DateTimeOffset.UtcNow; }
    public void Fail(string error) { Status = AgentExecutionStatus.Failed; Error = error; CompletedAt = DateTimeOffset.UtcNow; }
    public void Cancel() { Status = AgentExecutionStatus.Cancelled; CompletedAt = DateTimeOffset.UtcNow; }
}

public sealed class Asset
{
    private Asset() { }
    public Asset(Guid tenantId, Guid scopeId, string address, TargetKind kind) { Id = Guid.NewGuid(); TenantId = tenantId; ScopeId = scopeId; Address = address; Kind = kind; LastSeenAt = DateTimeOffset.UtcNow; }
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid ScopeId { get; private set; }
    public string Address { get; private set; } = string.Empty;
    public TargetKind Kind { get; private set; }
    public bool IsOnline { get; private set; }
    public DateTimeOffset LastSeenAt { get; private set; }
    public void MarkSeen(bool online) { IsOnline = online; LastSeenAt = DateTimeOffset.UtcNow; }
}

public sealed class Finding
{
    private Finding() { }
    public Finding(Guid tenantId, Guid? assetId, string title, FindingSeverity severity) { Id = Guid.NewGuid(); TenantId = tenantId; AssetId = assetId; Title = title; Severity = severity; CreatedAt = DateTimeOffset.UtcNow; }
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid? AssetId { get; private set; }
    public string Title { get; private set; } = string.Empty;
    public FindingSeverity Severity { get; private set; }
    public string? Description { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
}

public sealed class Evidence
{
    private Evidence() { }
    public Evidence(Guid tenantId, Guid findingId, string source, string summary, string sha256) { Id = Guid.NewGuid(); TenantId = tenantId; FindingId = findingId; Source = source; Summary = summary; Sha256 = sha256; CollectedAt = DateTimeOffset.UtcNow; }
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid FindingId { get; private set; }
    public string Source { get; private set; } = string.Empty;
    public string Summary { get; private set; } = string.Empty;
    public string Sha256 { get; private set; } = string.Empty;
    public DateTimeOffset CollectedAt { get; private set; }
}

public sealed class ApprovalRequest
{
    private ApprovalRequest() { }
    public ApprovalRequest(Guid tenantId, Guid jobId, Guid requestedBy, string reason) { Id = Guid.NewGuid(); TenantId = tenantId; JobId = jobId; RequestedBy = requestedBy; Reason = reason; CreatedAt = DateTimeOffset.UtcNow; }
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid JobId { get; private set; }
    public Guid RequestedBy { get; private set; }
    public string Reason { get; private set; } = string.Empty;
    public Guid? ApprovedBy { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? DecidedAt { get; private set; }
    public bool IsApproved { get; private set; }
    public void Approve(Guid principal) { ApprovedBy = principal; DecidedAt = DateTimeOffset.UtcNow; IsApproved = true; }
}

public sealed class AuditEvent
{
    private AuditEvent() { }
    public AuditEvent(Guid tenantId, Guid? actorId, string action, string resourceType, Guid? resourceId, string detail) { Id = Guid.NewGuid(); TenantId = tenantId; ActorId = actorId; Action = action; ResourceType = resourceType; ResourceId = resourceId; Detail = detail; OccurredAt = DateTimeOffset.UtcNow; }
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid? ActorId { get; private set; }
    public string Action { get; private set; } = string.Empty;
    public string ResourceType { get; private set; } = string.Empty;
    public Guid? ResourceId { get; private set; }
    public string Detail { get; private set; } = string.Empty;
    public DateTimeOffset OccurredAt { get; private set; }
}

public sealed class AIAnalysis
{
    private AIAnalysis() { }
    public AIAnalysis(Guid tenantId, Guid jobId, string provider, string model, string summary) { Id = Guid.NewGuid(); TenantId = tenantId; JobId = jobId; Provider = provider; Model = model; Summary = summary; CreatedAt = DateTimeOffset.UtcNow; }
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid JobId { get; private set; }
    public string Provider { get; private set; } = string.Empty;
    public string Model { get; private set; } = string.Empty;
    public string Summary { get; private set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; private set; }
}

public sealed class Notification
{
    private Notification() { }
    public Notification(Guid tenantId, string channel, string message) { Id = Guid.NewGuid(); TenantId = tenantId; Channel = channel; Message = message; CreatedAt = DateTimeOffset.UtcNow; }
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public string Channel { get; private set; } = string.Empty;
    public string Message { get; private set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; private set; }
}
