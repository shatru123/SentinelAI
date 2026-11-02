using Microsoft.EntityFrameworkCore;
using SentinelAI.Contracts;
using SentinelAI.Domain;
using SentinelAI.Security.Policy;

namespace SentinelAI.Application;

public interface IAppDbContext
{
    DbSet<Tenant> Tenants { get; }
    DbSet<User> Users { get; }
    DbSet<TargetScope> TargetScopes { get; }
    DbSet<ScanPolicy> ScanPolicies { get; }
    DbSet<AgentJob> AgentJobs { get; }
    DbSet<AgentExecution> AgentExecutions { get; }
    DbSet<Asset> Assets { get; }
    DbSet<Finding> Findings { get; }
    DbSet<Evidence> Evidence { get; }
    DbSet<ApprovalRequest> ApprovalRequests { get; }
    DbSet<AuditEvent> AuditEvents { get; }
    DbSet<AIAnalysis> AIAnalyses { get; }
    DbSet<Notification> Notifications { get; }
    DbSet<WorkerRegistration> Workers { get; }
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}

public sealed record PrincipalContext(Guid TenantId, Guid UserId, string Subject, UserRole Role)
{
    public bool CanRead => Role is UserRole.Admin or UserRole.SecurityAnalyst or UserRole.Viewer;
    public bool CanOperate => Role is UserRole.Admin or UserRole.SecurityAnalyst;
    public CurrentUserResponse ToResponse() => new(Subject, TenantId, UserId, Role.ToString());
}

public interface IScanJobQueue
{
    ValueTask EnqueueAsync(Guid jobId, CancellationToken cancellationToken = default);
    IAsyncEnumerable<ScanJobDelivery> ReadAllAsync(CancellationToken cancellationToken = default);
    ValueTask RequestCancellationAsync(Guid jobId, CancellationToken cancellationToken = default);
    IAsyncEnumerable<Guid> ReadCancellationsAsync(CancellationToken cancellationToken = default);
}

public sealed record ScanJobDelivery(Guid JobId, int Attempt,
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

public sealed class ScopeService(IAppDbContext db, ITargetScopeValidator validator) : IScopeService
{
    public async Task<ScopeResponse> CreateAsync(PrincipalContext principal, CreateScopeRequest request, CancellationToken cancellationToken)
    {
        if (!principal.CanOperate) throw new UnauthorizedAccessException("The current role cannot create scopes.");
        var scope = new TargetScope(principal.TenantId, request.Name.Trim(), principal.UserId, request.ExpiresAt);
        scope.Configure(request.Targets, request.Exclusions ?? [], request.ApprovedOperationProfiles, request.RequestsPerMinute,
            request.MaxExecutionSeconds, request.AuthorizationEvidence.Trim(), false);
        scope.ConfigureVerifications((request.PublicTargetAuthorizations ?? []).Select(x =>
            new PublicTargetVerification(x.Target, x.Evidence, x.Verifier, x.Method, x.VerifiedAt)).ToArray());
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

    private static ScopeResponse ToResponse(TargetScope scope) => new(scope.Id, scope.Name, scope.TenantId, scope.Targets, scope.ApprovedOperationProfiles, scope.ExpiresAt, scope.IsActive);
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
        db.AgentExecutions.Add(new AgentExecution(job.Id, "MockNetworkDiscoveryAgent"));
        db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "scan.created", nameof(AgentJob), job.Id, "Phase 1 mock assessment queued."));
        await db.SaveChangesAsync(cancellationToken);
        await queue.EnqueueAsync(job.Id, cancellationToken);
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
        await db.SaveChangesAsync(cancellationToken);
        await queue.RequestCancellationAsync(job.Id, cancellationToken);
        return true;
    }

    private static ScanResponse ToResponse(AgentJob job) => new(job.Id, job.ScopeId, job.Status, job.CreatedAt, job.ExpiresAt, job.OperationProfile);
}

public sealed class ScopeValidationException(IReadOnlyList<string> errors) : Exception(string.Join(" ", errors))
{
    public IReadOnlyList<string> Errors { get; } = errors;
}
