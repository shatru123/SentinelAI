using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using SentinelAI.Contracts;
using SentinelAI.Domain;
using SentinelAI.Security.Policy;

namespace SentinelAI.Application;

public interface IAppDbContext : IAsyncDisposable, IDisposable
{
    DbSet<Tenant> Tenants { get; }
    DbSet<User> Users { get; }
    DbSet<TargetScope> TargetScopes { get; }
    DbSet<ScanPolicy> ScanPolicies { get; }
    DbSet<AgentJob> AgentJobs { get; }
    DbSet<AgentExecution> AgentExecutions { get; }
    DbSet<Asset> Assets { get; }
    DbSet<AssetService> AssetServices { get; }
    DbSet<Finding> Findings { get; }
    DbSet<Evidence> Evidence { get; }
    DbSet<ApprovalRequest> ApprovalRequests { get; }
    DbSet<AuditEvent> AuditEvents { get; }
    DbSet<AIAnalysis> AIAnalyses { get; }
    DbSet<Notification> Notifications { get; }
    DbSet<WorkerRegistration> Workers { get; }
    DbSet<PublicTargetAuthorization> PublicTargetAuthorizations { get; }
    DbSet<OutboxMessage> OutboxMessages { get; }
    DbSet<WebAssessment> WebAssessments { get; }
    DbSet<WebAssessmentEndpoint> WebAssessmentEndpoints { get; }
    DbSet<AssessmentScreenshot> AssessmentScreenshots { get; }
    DbSet<WebAssessmentCheck> WebAssessmentChecks { get; }
    DbSet<VulnerabilityCatalogEntry> VulnerabilityCatalogEntries { get; }
    DbSet<VulnerabilityCvssMetric> VulnerabilityCvssMetrics { get; }
    DbSet<VulnerabilityKevEntry> VulnerabilityKevEntries { get; }
    DbSet<VulnerabilityEpssScore> VulnerabilityEpssScores { get; }
    DbSet<VulnerabilitySyncCheckpoint> VulnerabilitySyncCheckpoints { get; }
    DbSet<SoftwareComponent> SoftwareComponents { get; }
    DbSet<AssetVulnerabilityMatch> AssetVulnerabilityMatches { get; }
    Task PersistWebAssessmentEndpointsAsync(Guid tenantId, Guid assessmentId, IReadOnlyCollection<WebAssessmentEndpoint> endpoints, CancellationToken cancellationToken = default);
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
    Task<IAppDbTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default);
}

public interface IAppDbContextFactory
{
    IAppDbContext CreateDbContext();
}

public interface IAppDbTransaction : IAsyncDisposable
{
    Task CommitAsync(CancellationToken cancellationToken = default);
}

public sealed record PrincipalContext(Guid TenantId, Guid UserId, string Subject, UserRole Role)
{
    public bool CanRead => Role is UserRole.Admin or UserRole.SecurityAnalyst or UserRole.Viewer;
    public bool CanOperate => Role is UserRole.Admin or UserRole.SecurityAnalyst;
    public CurrentUserResponse ToResponse() => new(Subject, TenantId, UserId, Role.ToString());
}

public sealed record AuthorizedInventoryTarget(TargetDefinition Definition, ValidatedExecutionTarget Validation);
public sealed record InventoryServiceObservation(string Protocol, int Port, string? Name = null, string? Version = null);
public sealed record InventoryObservation(string Address, TargetKind Kind, bool IsOnline, IReadOnlyCollection<InventoryServiceObservation> Services, bool ReachabilityConfirmed = false);

public interface IPassiveInventoryAdapter
{
    Task<IReadOnlyCollection<InventoryObservation>> CollectAsync(
        IReadOnlyCollection<AuthorizedInventoryTarget> targets,
        int requestsPerMinute,
        CancellationToken cancellationToken = default);
}

public static class InventoryOperationProfiles
{
    public const string MockPassive = "mock-passive";
    public const string NetworkInventoryPassive = "network-inventory-passive";
}

public static class WebAssessmentOperationProfiles
{
    public const string Passive = "web-assessment-passive";
    public const string SafeActive = "web-assessment-safe-active";
    public static bool IsWeb(string profile) => profile.Equals(Passive, StringComparison.OrdinalIgnoreCase) || profile.Equals(SafeActive, StringComparison.OrdinalIgnoreCase);
}

public interface IScanJobQueue
{
    ValueTask EnqueueAsync(Guid jobId, CancellationToken cancellationToken = default);
    ValueTask EnqueueAsync(Guid jobId, Guid tenantId, CancellationToken cancellationToken = default);
    IAsyncEnumerable<ScanJobDelivery> ReadAllAsync(Guid? tenantId = null, string? workerIdentity = null, CancellationToken cancellationToken = default);
    ValueTask RequestCancellationAsync(Guid jobId, CancellationToken cancellationToken = default);
    ValueTask RequestCancellationAsync(Guid jobId, Guid tenantId, string workerIdentity, CancellationToken cancellationToken = default);
    IAsyncEnumerable<Guid> ReadCancellationsAsync(Guid tenantId, string workerIdentity, CancellationToken cancellationToken = default);
}

public interface IImmediateScanJobQueue { }

public sealed record ScanJobDelivery(Guid JobId, Guid TenantId, string? WorkerIdentity, int Attempt,
    Func<CancellationToken, ValueTask> AcknowledgeAsync,
    Func<bool, CancellationToken, ValueTask> RejectAsync);

public interface IScopeService
{
    Task<ScopeResponse> CreateAsync(PrincipalContext principal, CreateScopeRequest request, CancellationToken cancellationToken);
    Task<PagedResponse<ScopeResponse>> ListAsync(PrincipalContext principal, int page, int pageSize, CancellationToken cancellationToken);
}

public interface IScanService
{
    Task<ScanResponse> CreateAsync(PrincipalContext principal, CreateScanRequest request, CancellationToken cancellationToken);
    Task<ScanResponse?> GetAsync(PrincipalContext principal, Guid id, CancellationToken cancellationToken);
    Task<bool> CancelAsync(PrincipalContext principal, Guid id, CancellationToken cancellationToken);
}

public interface IPublicTargetAuthorizationService
{
    Task<PublicTargetAuthorizationResponse> RequestAsync(PrincipalContext principal, PublicTargetAuthorizationRequest request, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<PublicTargetAuthorizationResponse>> ListAsync(PrincipalContext principal, CancellationToken cancellationToken);
    Task<PublicTargetAuthorizationResponse?> ApproveAsync(PrincipalContext principal, Guid id, PublicTargetAuthorizationApprovalRequest request, CancellationToken cancellationToken);
    Task<bool> RevokeAsync(PrincipalContext principal, Guid id, CancellationToken cancellationToken);
}

public interface IWebAssessmentService
{
    Task<WebAssessmentResponse> CreateAsync(PrincipalContext principal, CreateWebAssessmentRequest request, CancellationToken cancellationToken);
    Task<WebAssessmentResponse?> GetAsync(PrincipalContext principal, Guid id, CancellationToken cancellationToken);
}

public sealed class ScopeService(IAppDbContext db, ITargetScopeValidator validator) : IScopeService
{
    public async Task<ScopeResponse> CreateAsync(PrincipalContext principal, CreateScopeRequest request, CancellationToken cancellationToken)
    {
        if (!principal.CanOperate) throw new UnauthorizedAccessException("The current role cannot create scopes.");
        if (request is null) throw new ScopeValidationException(["A scope request is required."]);
        if (string.IsNullOrWhiteSpace(request.Name)) throw new ScopeValidationException(["A scope name is required."]);
        if (request.Targets is null || request.Targets.Count == 0) throw new ScopeValidationException(["At least one target is required."]);
        if (request.ApprovedOperationProfiles is null || request.ApprovedOperationProfiles.Count == 0) throw new ScopeValidationException(["At least one operation profile is required."]);
        if (string.IsNullOrWhiteSpace(request.AuthorizationEvidence)) throw new ScopeValidationException(["Authorization evidence is required."]);
        var scope = new TargetScope(principal.TenantId, request.Name.Trim(), principal.UserId, request.ExpiresAt);
        scope.Configure(request.Targets, request.Exclusions ?? [], request.ApprovedOperationProfiles, request.RequestsPerMinute,
            request.MaxExecutionSeconds, request.AuthorizationEvidence.Trim(), false, request.AllowSubdomains, request.MaxTotalRequests, request.MaxConcurrentRequests, request.MaxPages, request.MaxCrawlDepth, request.MaxResponseBytes);
        if (request.HostingMode is not null) scope.ConfigureWebHosting(request.HostingMode.Value, request.PrivateWorkerIdentity, request.PrivateNetworkRanges);
        var authorizationIds = request.PublicTargetAuthorizationIds ?? [];
        if (authorizationIds.Count > 0)
        {
            var authorizations = await db.PublicTargetAuthorizations
                .Where(x => x.TenantId == principal.TenantId && authorizationIds.Contains(x.Id))
                .ToListAsync(cancellationToken);
            if (authorizations.Count != authorizationIds.Count) throw new ScopeValidationException(["One or more public target authorizations were not found in this tenant."]);
            var verifications = new List<PublicTargetVerification>();
            foreach (var authorization in authorizations)
            {
                try { verifications.Add(authorization.ToVerification()); }
                catch (InvalidOperationException exception) { throw new ScopeValidationException([exception.Message]); }
            }
            scope.ConfigureVerifications(verifications);
        }
        var validation = validator.ValidateDefinition(scope, principal.TenantId, DateTimeOffset.UtcNow);
        if (!validation.IsValid) throw new ScopeValidationException(validation.Errors);
        db.TargetScopes.Add(scope);
        db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "scope.created", nameof(TargetScope), scope.Id, "Authorized scope registered."));
        await db.SaveChangesAsync(cancellationToken);
        return ToResponse(scope);
    }

    public async Task<PagedResponse<ScopeResponse>> ListAsync(PrincipalContext principal, int page, int pageSize, CancellationToken cancellationToken)
    {
        var query = db.TargetScopes.AsNoTracking().Where(x => x.TenantId == principal.TenantId).OrderByDescending(x => x.CreatedAt);
        var total = await query.CountAsync(cancellationToken);
        var items = await query.Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(cancellationToken);
        return new PagedResponse<ScopeResponse>(items.Select(ToResponse).ToArray(), page, pageSize, total);
    }

    private static ScopeResponse ToResponse(TargetScope scope) => new(scope.Id, scope.Name, scope.TenantId, scope.Targets, scope.ApprovedOperationProfiles, scope.ExpiresAt, scope.IsActive, scope.WebHostingMode, scope.PrivateWorkerIdentity);
}

public sealed class ScanService(IAppDbContext db, ITargetScopeValidator validator, IScanJobQueue queue) : IScanService
{
    public async Task<ScanResponse> CreateAsync(PrincipalContext principal, CreateScanRequest request, CancellationToken cancellationToken)
    {
        if (!principal.CanOperate) throw new UnauthorizedAccessException("The current role cannot create scans.");
        var scope = await db.TargetScopes.SingleOrDefaultAsync(x => x.Id == request.ScopeId && x.TenantId == principal.TenantId, cancellationToken)
            ?? throw new KeyNotFoundException("Scope was not found.");
        var validation = validator.ValidateDefinition(scope, principal.TenantId, DateTimeOffset.UtcNow);
        if (!validation.IsValid) throw new ScopeValidationException(validation.Errors);
        if (!scope.ApprovedOperationProfiles.Contains(request.OperationProfile, StringComparer.OrdinalIgnoreCase))
            throw new ScopeValidationException(["Operation profile is not approved by the scope."]);

        var job = new AgentJob(principal.TenantId, scope.Id, principal.UserId, request.OperationProfile);
        db.AgentJobs.Add(job);
        db.AgentExecutions.Add(new AgentExecution(job.Id, WebAssessmentOperationProfiles.IsWeb(request.OperationProfile) ? "AuthorizedWebAssessmentAgent" : "MockNetworkDiscoveryAgent"));
        if (WebAssessmentOperationProfiles.IsWeb(request.OperationProfile))
        {
            var webTarget = scope.Targets.FirstOrDefault(x => x.Kind == TargetKind.Web)?.Value
                ?? throw new ScopeValidationException(["A web assessment scope must contain a web target."]);
            db.WebAssessments.Add(new WebAssessment(job.TenantId, job.Id, scope.Id, webTarget, request.OperationProfile, scope.WebHostingMode ?? WebHostingMode.Public));
        }
        db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "scan.created", nameof(AgentJob), job.Id, "Phase 1 mock assessment queued."));
        var workerRoute = scope.WebHostingMode == WebHostingMode.Private ? scope.PrivateWorkerIdentity : null;
        db.OutboxMessages.Add(new OutboxMessage(principal.TenantId, OutboxMessageTypes.ScanJob,
            OutboxMessagePayload.Serialize(new OutboxJobEnvelope(job.Id, principal.TenantId, workerRoute))));
        await using (var transaction = await db.BeginTransactionAsync(cancellationToken))
        {
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        if (queue is IImmediateScanJobQueue) await queue.EnqueueAsync(job.Id, principal.TenantId, cancellationToken);
        return ToResponse(job);
    }

    public async Task<ScanResponse?> GetAsync(PrincipalContext principal, Guid id, CancellationToken cancellationToken)
    {
        var job = await db.AgentJobs.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id && x.TenantId == principal.TenantId, cancellationToken);
        return job is null ? null : ToResponse(job);
    }

    public async Task<bool> CancelAsync(PrincipalContext principal, Guid id, CancellationToken cancellationToken)
    {
        if (!principal.CanOperate) throw new UnauthorizedAccessException("The current role cannot cancel scans.");
        var job = await db.AgentJobs.SingleOrDefaultAsync(x => x.Id == id && x.TenantId == principal.TenantId, cancellationToken);
        if (job is null) return false;
        job.Cancel();
        db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "scan.cancelled", nameof(AgentJob), job.Id, "Cancellation requested by operator."));
        if (!string.IsNullOrWhiteSpace(job.AssignedWorkerIdentity))
            db.OutboxMessages.Add(new OutboxMessage(principal.TenantId, OutboxMessageTypes.Cancellation,
                OutboxMessagePayload.Serialize(new OutboxCancellationEnvelope(job.Id, principal.TenantId, job.AssignedWorkerIdentity!))));
        await using (var transaction = await db.BeginTransactionAsync(cancellationToken))
        {
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        if (queue is IImmediateScanJobQueue && !string.IsNullOrWhiteSpace(job.AssignedWorkerIdentity))
            await queue.RequestCancellationAsync(job.Id, principal.TenantId, job.AssignedWorkerIdentity!, cancellationToken);
        return true;
    }

    private static ScanResponse ToResponse(AgentJob job) => new(job.Id, job.ScopeId, job.Status, job.CreatedAt, job.ExpiresAt, job.OperationProfile);
}

public sealed class WebAssessmentService(IAppDbContext db, IScopeService scopes, IScanService scans) : IWebAssessmentService
{
    public async Task<WebAssessmentResponse> CreateAsync(PrincipalContext principal, CreateWebAssessmentRequest request, CancellationToken cancellationToken)
    {
        if (!principal.CanOperate) throw new UnauthorizedAccessException("The current role cannot create web assessments.");
        if (!Uri.TryCreate(request.TargetUrl, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || string.IsNullOrWhiteSpace(uri.Host))
            throw new ScopeValidationException(["A valid HTTP(S) target URL is required."]);
        if (request.HostingMode == WebHostingMode.Private && string.IsNullOrWhiteSpace(request.PrivateWorkerIdentity))
            throw new ScopeValidationException(["A private assessment worker is required for private targets."]);
        if (request.HostingMode == WebHostingMode.Private)
        {
            var privateWorker = await db.Workers.AsNoTracking().SingleOrDefaultAsync(x => x.TenantId == principal.TenantId && x.Identity == request.PrivateWorkerIdentity!.Trim(), cancellationToken);
            if (privateWorker is null || privateWorker.Status == WorkerStatus.Disabled || !privateWorker.Capabilities.Contains("web-assessment", StringComparer.OrdinalIgnoreCase) || !privateWorker.Capabilities.Contains("private-web-assessment", StringComparer.OrdinalIgnoreCase))
                throw new ScopeValidationException(["The selected private worker is not enrolled with the required web assessment capabilities."]);
            var ranges = request.PrivateNetworkRanges?.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray() ?? [];
            if (ranges.Length == 0)
                throw new ScopeValidationException(["Private web assessments require administrator-approved private network ranges."]);
            if (ranges.Length > 0 && !privateWorker.PrivateAssessmentApproved)
                throw new ScopeValidationException(["The selected private worker has no valid administrator-approved private network authorization."]);
            if (ranges.Length > 0 && ranges.Any(range => !TargetScopeValidator.IsValidPrivateNetworkRange(range) || !privateWorker.ApprovedPrivateNetworkRanges.Any(approved => TargetScopeValidator.IsNetworkRangeContainedBy(range, approved))))
                throw new ScopeValidationException(["Every requested private network range must be contained by the worker's administrator-approved ranges."]);
        }
        var profile = request.OperationProfile.Equals(WebAssessmentOperationProfiles.SafeActive, StringComparison.OrdinalIgnoreCase)
            ? WebAssessmentOperationProfiles.SafeActive : WebAssessmentOperationProfiles.Passive;
        var scope = await scopes.CreateAsync(principal, new CreateScopeRequest(
            request.Name, [new TargetDefinition(TargetKind.Web, uri.ToString())], request.Exclusions ?? [], [profile],
            request.RequestsPerMinute, request.MaxExecutionSeconds, request.AuthorizationEvidence, request.ExpiresAt,
            false, null, request.PublicTargetAuthorizationIds, request.AllowSubdomains, request.HostingMode, request.PrivateWorkerIdentity, request.PrivateNetworkRanges,
            request.MaxTotalRequests, request.MaxConcurrentRequests, request.MaxPages, request.MaxCrawlDepth, request.MaxResponseBytes), cancellationToken);
        var scan = await scans.CreateAsync(principal, new CreateScanRequest(scope.Id, profile), cancellationToken);
        var assessment = await db.WebAssessments.SingleAsync(x => x.AgentJobId == scan.Id && x.TenantId == principal.TenantId, cancellationToken);
        return ToResponse(assessment, scan);
    }

    public async Task<WebAssessmentResponse?> GetAsync(PrincipalContext principal, Guid id, CancellationToken cancellationToken)
    {
        var assessment = await db.WebAssessments.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id && x.TenantId == principal.TenantId, cancellationToken);
        if (assessment is null) return null;
        var job = await db.AgentJobs.AsNoTracking().SingleAsync(x => x.Id == assessment.AgentJobId && x.TenantId == principal.TenantId, cancellationToken);
        return ToResponse(assessment, new ScanResponse(job.Id, job.ScopeId, job.Status, job.CreatedAt, job.ExpiresAt, job.OperationProfile));
    }

    private static WebAssessmentResponse ToResponse(WebAssessment assessment, ScanResponse scan)
        => new(assessment.Id, assessment.AgentJobId, assessment.ScopeId, assessment.TargetUrl, assessment.Profile, assessment.HostingMode, assessment.Status, scan.Status, assessment.CreatedAt, assessment.StartedAt, assessment.CompletedAt, assessment.DiscoveredEndpointCount, assessment.ReportStorageKey);

}

public static class OutboxMessageTypes
{
    public const string ScanJob = "scan-job";
    public const string Cancellation = "cancellation";
}

public sealed record OutboxJobEnvelope(Guid JobId, Guid TenantId, string? WorkerIdentity = null);
public sealed record OutboxCancellationEnvelope(Guid JobId, Guid TenantId, string WorkerIdentity);

public static class OutboxMessagePayload
{
    public static string Serialize<T>(T value) => System.Text.Json.JsonSerializer.Serialize(value);
    public static T Deserialize<T>(string value) => System.Text.Json.JsonSerializer.Deserialize<T>(value) ?? throw new InvalidOperationException("Outbox payload is invalid.");
}

public sealed class PublicTargetAuthorizationService(IAppDbContext db) : IPublicTargetAuthorizationService
{
    public async Task<PublicTargetAuthorizationResponse> RequestAsync(PrincipalContext principal, PublicTargetAuthorizationRequest request, CancellationToken cancellationToken)
    {
        if (!principal.CanOperate) throw new UnauthorizedAccessException("The current role cannot request authorization.");
        if (string.IsNullOrWhiteSpace(request.Target) || string.IsNullOrWhiteSpace(request.Reason)) throw new ScopeValidationException(["Target and reason are required."]);
        var authorization = new PublicTargetAuthorization(principal.TenantId, request.Target, principal.UserId, request.Reason);
        db.PublicTargetAuthorizations.Add(authorization);
        db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "public-target.authorization.requested", nameof(PublicTargetAuthorization), authorization.Id, "Public target authorization requested."));
        await db.SaveChangesAsync(cancellationToken);
        return ToResponse(authorization);
    }

    public async Task<IReadOnlyCollection<PublicTargetAuthorizationResponse>> ListAsync(PrincipalContext principal, CancellationToken cancellationToken)
    {
        var items = await db.PublicTargetAuthorizations.AsNoTracking().Where(x => x.TenantId == principal.TenantId).OrderByDescending(x => x.CreatedAt).ToListAsync(cancellationToken);
        return items.Select(ToResponse).ToArray();
    }

    public async Task<PublicTargetAuthorizationResponse?> ApproveAsync(PrincipalContext principal, Guid id, PublicTargetAuthorizationApprovalRequest request, CancellationToken cancellationToken)
    {
        if (principal.Role != UserRole.Admin) throw new UnauthorizedAccessException("Only administrators may approve public target authorization.");
        var authorization = await db.PublicTargetAuthorizations.SingleOrDefaultAsync(x => x.Id == id && x.TenantId == principal.TenantId, cancellationToken);
        if (authorization is null) return null;
        authorization.Approve(principal.UserId, request.Evidence, request.Method, request.ExpiresAt);
        db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "public-target.authorization.approved", nameof(PublicTargetAuthorization), id, "Public target authorization approved by an administrator."));
        await db.SaveChangesAsync(cancellationToken);
        return ToResponse(authorization);
    }

    public async Task<bool> RevokeAsync(PrincipalContext principal, Guid id, CancellationToken cancellationToken)
    {
        if (principal.Role != UserRole.Admin) throw new UnauthorizedAccessException("Only administrators may revoke public target authorization.");
        var authorization = await db.PublicTargetAuthorizations.SingleOrDefaultAsync(x => x.Id == id && x.TenantId == principal.TenantId, cancellationToken);
        if (authorization is null) return false;
        authorization.Revoke();
        var scopes = await db.TargetScopes.Where(x => x.TenantId == principal.TenantId).ToListAsync(cancellationToken);
        foreach (var scope in scopes) scope.RevokePublicAuthorization(id);
        db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "public-target.authorization.revoked", nameof(PublicTargetAuthorization), id, "Public target authorization revoked."));
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    private static PublicTargetAuthorizationResponse ToResponse(PublicTargetAuthorization authorization)
        => new(authorization.Id, authorization.Target, authorization.GetStatus(DateTimeOffset.UtcNow), authorization.RequestedBy, authorization.ApprovedBy, authorization.CreatedAt, authorization.ApprovedAt, authorization.ExpiresAt);
}

public sealed class ScopeValidationException(IReadOnlyList<string> errors) : Exception(string.Join(" ", errors))
{
    public IReadOnlyList<string> Errors { get; } = errors;
}
