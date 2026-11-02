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
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum WorkerStatus { Registered, Healthy, Unhealthy, Disabled }
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum PublicTargetAuthorizationStatus { Requested, Approved, Revoked, Expired }

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
    public bool AllowSubdomains { get; private set; }
    public List<PublicTargetVerification> PublicTargetVerifications { get; private set; } = [];
    public DateTimeOffset ExpiresAt { get; private set; }
    public Guid CreatedBy { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public bool IsActive => ExpiresAt > DateTimeOffset.UtcNow;
    public byte[] RowVersion { get; private set; } = Guid.NewGuid().ToByteArray();

    public void Configure(IReadOnlyCollection<TargetDefinition> targets, IReadOnlyCollection<string> exclusions,
        IReadOnlyCollection<string> profiles, int requestsPerMinute, int maxExecutionSeconds,
        string authorizationEvidence, bool publicTargetOwnershipVerified, bool allowSubdomains = false)
    {
        Targets = targets.ToList(); Exclusions = exclusions.ToList(); ApprovedOperationProfiles = profiles.ToList();
        RequestsPerMinute = requestsPerMinute; MaxExecutionSeconds = maxExecutionSeconds;
        AuthorizationEvidence = authorizationEvidence; PublicTargetOwnershipVerified = publicTargetOwnershipVerified; AllowSubdomains = allowSubdomains;
    }

    public void ConfigureVerifications(IReadOnlyCollection<PublicTargetVerification> verifications)
    {
        PublicTargetVerifications = verifications.ToList();
        // Kept for migration/source compatibility only. The policy engine never trusts this flag.
        PublicTargetOwnershipVerified = false;
    }

    public void RevokePublicAuthorization(Guid authorizationId)
        => PublicTargetVerifications = PublicTargetVerifications.Where(x => x.AuthorizationId != authorizationId).ToList();
}

public sealed record TargetDefinition(TargetKind Kind, string Value);
public sealed record PublicTargetVerification(string Target, string Evidence, string Verifier, string Method, DateTimeOffset VerifiedAt, DateTimeOffset? ExpiresAt = null, Guid? AuthorizationId = null);

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
    public string? AssignedWorkerIdentity { get; private set; }
    public string? LeaseOwnerWorkerId { get; private set; }
    public DateTimeOffset? LeaseAcquiredAt { get; private set; }
    public DateTimeOffset? LeaseExpiresAt { get; private set; }
    public DateTimeOffset? LastLeaseHeartbeatAt { get; private set; }
    public DateTimeOffset? CancellationRequestedAt { get; private set; }
    public string? FailureReason { get; private set; }
    public byte[] RowVersion { get; private set; } = Guid.NewGuid().ToByteArray();
    public bool IsCancellationRequested => CancellationRequestedAt is not null || Status == ScanJobStatus.Cancelled;
    public void Start() { if (Status != ScanJobStatus.Queued) throw new InvalidOperationException("Only queued jobs can start."); Status = ScanJobStatus.Running; StartedAt = DateTimeOffset.UtcNow; RowVersion = Guid.NewGuid().ToByteArray(); }
    public bool TryStart() { if (Status != ScanJobStatus.Queued) return false; Start(); return true; }
    public bool TryClaim(string workerIdentity)
    {
        if (string.IsNullOrWhiteSpace(workerIdentity) || Status != ScanJobStatus.Queued || IsCancellationRequested) return false;
        if (AssignedWorkerIdentity is not null && !AssignedWorkerIdentity.Equals(workerIdentity.Trim(), StringComparison.Ordinal)) return false;
        AssignedWorkerIdentity ??= workerIdentity.Trim(); RowVersion = Guid.NewGuid().ToByteArray();
        return true;
    }
    public bool TryAcquireLease(string workerIdentity, DateTimeOffset now, TimeSpan duration)
    {
        if (string.IsNullOrWhiteSpace(workerIdentity) || duration <= TimeSpan.Zero || Status is ScanJobStatus.Completed or ScanJobStatus.Failed or ScanJobStatus.Cancelled or ScanJobStatus.Expired) return false;
        if (Status == ScanJobStatus.Running && LeaseExpiresAt is not null && LeaseExpiresAt > now) return false;
        if (Status == ScanJobStatus.Running) RecoverExpiredLease(now);
        if (Status != ScanJobStatus.Queued || IsCancellationRequested) return false;
        Status = ScanJobStatus.Running;
        StartedAt = now;
        AssignedWorkerIdentity = workerIdentity.Trim();
        LeaseOwnerWorkerId = AssignedWorkerIdentity;
        LeaseAcquiredAt = now;
        LeaseExpiresAt = now.Add(duration);
        LastLeaseHeartbeatAt = now;
        FailureReason = null;
        RowVersion = Guid.NewGuid().ToByteArray();
        return true;
    }
    public bool RenewLease(string workerIdentity, DateTimeOffset now, TimeSpan duration)
    {
        if (Status != ScanJobStatus.Running || !string.Equals(LeaseOwnerWorkerId, workerIdentity?.Trim(), StringComparison.Ordinal) || LeaseExpiresAt is null || LeaseExpiresAt <= now) return false;
        LeaseExpiresAt = now.Add(duration);
        LastLeaseHeartbeatAt = now;
        RowVersion = Guid.NewGuid().ToByteArray();
        return true;
    }
    public bool HasActiveLease(DateTimeOffset now) => Status == ScanJobStatus.Running && LeaseExpiresAt is not null && LeaseExpiresAt > now;
    public bool IsLeaseOwnedBy(string workerIdentity, DateTimeOffset now) => HasActiveLease(now) && string.Equals(LeaseOwnerWorkerId, workerIdentity?.Trim(), StringComparison.Ordinal);
    public void RecoverExpiredLease(DateTimeOffset now)
    {
        if (Status == ScanJobStatus.Running && (LeaseExpiresAt is null || LeaseExpiresAt <= now))
        {
            Status = ScanJobStatus.Queued;
            StartedAt = null;
            AssignedWorkerIdentity = null;
            LeaseOwnerWorkerId = null;
            LeaseAcquiredAt = null;
            LeaseExpiresAt = null;
            LastLeaseHeartbeatAt = null;
            FailureReason = "Recovered after lease expiration.";
            RowVersion = Guid.NewGuid().ToByteArray();
        }
    }
    public void ReleaseLeaseForRetry(string reason)
    {
        if (Status != ScanJobStatus.Running) return;
        Status = ScanJobStatus.Queued;
        StartedAt = null;
        AssignedWorkerIdentity = null;
        LeaseOwnerWorkerId = null;
        LeaseAcquiredAt = null;
        LeaseExpiresAt = null;
        LastLeaseHeartbeatAt = null;
        FailureReason = reason;
        RowVersion = Guid.NewGuid().ToByteArray();
    }
    public void Complete() { if (Status != ScanJobStatus.Running) throw new InvalidOperationException("Only running jobs can complete."); Status = ScanJobStatus.Completed; CompletedAt = DateTimeOffset.UtcNow; RowVersion = Guid.NewGuid().ToByteArray(); }
    public void Fail(string reason) { if (Status is ScanJobStatus.Completed or ScanJobStatus.Cancelled or ScanJobStatus.Expired) return; Status = ScanJobStatus.Failed; FailureReason = reason; CompletedAt = DateTimeOffset.UtcNow; RowVersion = Guid.NewGuid().ToByteArray(); }
    public void Cancel() { if (Status is ScanJobStatus.Completed or ScanJobStatus.Failed or ScanJobStatus.Cancelled or ScanJobStatus.Expired) return; CancellationRequestedAt ??= DateTimeOffset.UtcNow; Status = ScanJobStatus.Cancelled; FailureReason = "Cancellation requested."; CompletedAt = DateTimeOffset.UtcNow; RowVersion = Guid.NewGuid().ToByteArray(); }
    public void Expire() { if (Status is ScanJobStatus.Queued or ScanJobStatus.Running) { Status = ScanJobStatus.Expired; CompletedAt = DateTimeOffset.UtcNow; RowVersion = Guid.NewGuid().ToByteArray(); } }
    public void RecoverInterrupted() => RecoverExpiredLease(DateTimeOffset.UtcNow);
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
    public void Start() { if (Status != AgentExecutionStatus.Pending) throw new InvalidOperationException("Only pending executions can start."); Status = AgentExecutionStatus.Running; StartedAt = DateTimeOffset.UtcNow; }
    public void Complete() { if (Status != AgentExecutionStatus.Running) throw new InvalidOperationException("Only running executions can complete."); Status = AgentExecutionStatus.Completed; CompletedAt = DateTimeOffset.UtcNow; }
    public void Fail(string error) { if (Status is AgentExecutionStatus.Completed or AgentExecutionStatus.Cancelled) return; Status = AgentExecutionStatus.Failed; Error = error; CompletedAt = DateTimeOffset.UtcNow; }
    public void Cancel() { if (Status is AgentExecutionStatus.Completed or AgentExecutionStatus.Cancelled) return; Status = AgentExecutionStatus.Cancelled; Error = "Cancellation requested."; CompletedAt = DateTimeOffset.UtcNow; }
    public void ResetForRetry() { if (Status == AgentExecutionStatus.Completed) return; Status = AgentExecutionStatus.Pending; StartedAt = null; CompletedAt = null; Error = "Recovered for retry."; }
}

public sealed class WorkerRegistration
{
    private WorkerRegistration() { }
    public WorkerRegistration(Guid tenantId, string identity, string version, IReadOnlyCollection<string> capabilities)
    {
        Id = Guid.NewGuid(); TenantId = tenantId; Identity = identity; Version = version;
        Capabilities = capabilities.ToList(); Status = WorkerStatus.Registered; RegisteredAt = DateTimeOffset.UtcNow;
        LastHeartbeatAt = RegisteredAt; MaximumCapacity = 1;
    }
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public string Identity { get; private set; } = string.Empty;
    public string Version { get; private set; } = string.Empty;
    public List<string> Capabilities { get; private set; } = [];
    public WorkerStatus Status { get; private set; }
    public DateTimeOffset RegisteredAt { get; private set; }
    public DateTimeOffset LastHeartbeatAt { get; private set; }
    public DateTimeOffset? LastJobAt { get; private set; }
    public int CurrentActiveJobs { get; private set; }
    public int MaximumCapacity { get; private set; }
    public DateTimeOffset? LastJobStartedAt { get; private set; }
    public DateTimeOffset? LastJobCompletedAt { get; private set; }
    public void Heartbeat(int activeJobs = 0, int capacity = 1, DateTimeOffset? lastJobStartedAt = null, DateTimeOffset? lastJobCompletedAt = null)
    {
        CurrentActiveJobs = Math.Max(0, activeJobs); MaximumCapacity = Math.Max(1, capacity); LastHeartbeatAt = DateTimeOffset.UtcNow; Status = WorkerStatus.Healthy;
        LastJobStartedAt = lastJobStartedAt ?? LastJobStartedAt; LastJobCompletedAt = lastJobCompletedAt ?? LastJobCompletedAt;
    }
    // Heartbeat capacity is telemetry only. Admission is enforced by the worker's local semaphore;
    // a delayed heartbeat must never reject a job that has already been admitted locally.
    public bool IsHealthyForAdmission(DateTimeOffset now, TimeSpan staleAfter) => Status is WorkerStatus.Registered or WorkerStatus.Healthy && LastHeartbeatAt >= now.Subtract(staleAfter);
    public bool IsAvailable(DateTimeOffset now, TimeSpan staleAfter) => IsHealthyForAdmission(now, staleAfter);
    public bool IsStale(DateTimeOffset now, TimeSpan staleAfter) => LastHeartbeatAt < now.Subtract(staleAfter);
    public void MarkJobStarted(DateTimeOffset now) { LastJobAt = now; LastJobStartedAt = now; }
    public void MarkJobCompleted(DateTimeOffset now) { LastJobAt = now; LastJobCompletedAt = now; }
    public void MarkJob() { MarkJobStarted(DateTimeOffset.UtcNow); Heartbeat(CurrentActiveJobs, MaximumCapacity, LastJobStartedAt, LastJobCompletedAt); }
    public void MarkUnhealthy() { Status = WorkerStatus.Unhealthy; }
}

public sealed class PublicTargetAuthorization
{
    private PublicTargetAuthorization() { }
    public PublicTargetAuthorization(Guid tenantId, string target, Guid requestedBy, string reason)
    {
        Id = Guid.NewGuid(); TenantId = tenantId; Target = target.Trim(); RequestedBy = requestedBy;
        Reason = reason.Trim(); Status = PublicTargetAuthorizationStatus.Requested; CreatedAt = DateTimeOffset.UtcNow;
    }
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public string Target { get; private set; } = string.Empty;
    public Guid RequestedBy { get; private set; }
    public string Reason { get; private set; } = string.Empty;
    public PublicTargetAuthorizationStatus Status { get; private set; }
    public string? Evidence { get; private set; }
    public string? VerificationMethod { get; private set; }
    public Guid? ApprovedBy { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? ApprovedAt { get; private set; }
    public DateTimeOffset? ExpiresAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }

    public void Approve(Guid approver, string evidence, string method, DateTimeOffset expiresAt)
    {
        if (approver == RequestedBy) throw new InvalidOperationException("The requester cannot approve their own authorization.");
        if (Status != PublicTargetAuthorizationStatus.Requested) throw new InvalidOperationException("Only requested authorizations can be approved.");
        if (string.IsNullOrWhiteSpace(evidence) || string.IsNullOrWhiteSpace(method)) throw new InvalidOperationException("Evidence and verification method are required.");
        if (expiresAt <= DateTimeOffset.UtcNow) throw new InvalidOperationException("Authorization expiry must be in the future.");
        ApprovedBy = approver; Evidence = evidence.Trim(); VerificationMethod = method.Trim(); ApprovedAt = DateTimeOffset.UtcNow;
        ExpiresAt = expiresAt; Status = PublicTargetAuthorizationStatus.Approved;
    }

    public void Revoke()
    {
        if (Status == PublicTargetAuthorizationStatus.Revoked) return;
        Status = PublicTargetAuthorizationStatus.Revoked; RevokedAt = DateTimeOffset.UtcNow;
    }

    public PublicTargetVerification ToVerification()
    {
        if (Status != PublicTargetAuthorizationStatus.Approved || ApprovedBy is null || ApprovedAt is null || ExpiresAt is null)
            throw new InvalidOperationException("Authorization is not currently approved.");
        if (ExpiresAt <= DateTimeOffset.UtcNow) { Status = PublicTargetAuthorizationStatus.Expired; throw new InvalidOperationException("Authorization has expired."); }
        return new PublicTargetVerification(Target, Evidence!, ApprovedBy.Value.ToString(), VerificationMethod!, ApprovedAt.Value, ExpiresAt, Id);
    }
}

public sealed class OutboxMessage
{
    private OutboxMessage() { }
    public OutboxMessage(Guid tenantId, string messageType, string payload)
    {
        Id = Guid.NewGuid(); TenantId = tenantId; MessageType = messageType; Payload = payload; CreatedAt = DateTimeOffset.UtcNow;
    }
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public string MessageType { get; private set; } = string.Empty;
    public string Payload { get; private set; } = string.Empty;
    public int AttemptCount { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? DispatchedAt { get; private set; }
    public DateTimeOffset? LastAttemptAt { get; private set; }
    public DateTimeOffset? NextAttemptAt { get; private set; }
    public string? LeaseOwner { get; private set; }
    public DateTimeOffset? LeaseAcquiredAt { get; private set; }
    public DateTimeOffset? LeaseExpiresAt { get; private set; }
    public string? LastError { get; private set; }
    public bool TryAcquireLease(string owner, DateTimeOffset now, TimeSpan duration)
    {
        if (DispatchedAt is not null || string.IsNullOrWhiteSpace(owner) || duration <= TimeSpan.Zero || (LeaseExpiresAt is not null && LeaseExpiresAt > now)) return false;
        LeaseOwner = owner; LeaseAcquiredAt = now; LeaseExpiresAt = now.Add(duration); return true;
    }
    public void MarkDispatched()
    {
        DispatchedAt = DateTimeOffset.UtcNow; LastError = null; NextAttemptAt = null; LeaseOwner = null; LeaseAcquiredAt = null; LeaseExpiresAt = null;
    }
    public void RecordFailure(string error, DateTimeOffset now, TimeSpan baseDelay, TimeSpan maxDelay)
    {
        AttemptCount++; LastAttemptAt = now; LastError = error[..Math.Min(error.Length, 2000)];
        var seconds = Math.Min(maxDelay.TotalSeconds, baseDelay.TotalSeconds * Math.Pow(2, Math.Min(AttemptCount - 1, 20)));
        NextAttemptAt = now.AddSeconds(Math.Max(1, seconds)); LeaseOwner = null; LeaseAcquiredAt = null; LeaseExpiresAt = null;
    }
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

public sealed class AssetService
{
    private AssetService() { }
    public AssetService(Guid tenantId, Guid assetId, string protocol, int port, string? name, string? version)
    {
        Id = Guid.NewGuid(); TenantId = tenantId; AssetId = assetId; Protocol = protocol.Trim().ToLowerInvariant(); Port = port;
        Name = string.IsNullOrWhiteSpace(name) ? null : name.Trim(); Version = string.IsNullOrWhiteSpace(version) ? null : version.Trim(); ObservedAt = DateTimeOffset.UtcNow;
    }
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid AssetId { get; private set; }
    public string Protocol { get; private set; } = string.Empty;
    public int Port { get; private set; }
    public string? Name { get; private set; }
    public string? Version { get; private set; }
    public DateTimeOffset ObservedAt { get; private set; }
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
