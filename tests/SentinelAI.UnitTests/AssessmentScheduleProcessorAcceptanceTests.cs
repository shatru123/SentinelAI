using System.Net;
using System.Runtime.CompilerServices;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;
using SentinelAI.Security.Policy;

namespace SentinelAI.UnitTests;

public sealed class AssessmentScheduleProcessorAcceptanceTests
{
    [Theory]
    [InlineData("scope-mutated")]
    [InlineData("scope-expired")]
    [InlineData("public-authorization-revoked")]
    [InlineData("worker-missing")]
    [InlineData("worker-disabled")]
    [InlineData("worker-unhealthy")]
    [InlineData("worker-stale")]
    [InlineData("worker-capability-removed")]
    [InlineData("worker-range-changed")]
    [InlineData("creator-deleted")]
    [InlineData("creator-role-downgraded")]
    public async Task Due_occurrence_fails_closed_when_authorization_is_no_longer_valid(string scenario)
    {
        var options = NewOptions();
        var now = DateTimeOffset.UtcNow;
        var tenant = new Tenant("Phase 4 authorization acceptance");
        var creatorId = Guid.NewGuid();
        var creator = new User(creatorId, tenant.Id, "schedule-creator", "Schedule creator", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "bounded-web-scope", creatorId, now.AddDays(6));
        var isPublic = scenario == "public-authorization-revoked";
        PublicTargetAuthorization? publicAuthorization = null;
        WorkerRegistration? worker = null;

        scope.Configure(
            [new TargetDefinition(TargetKind.Web, isPublic ? "https://example.test/" : "https://10.1.2.3/")],
            [],
            [WebAssessmentOperationProfiles.Passive],
            30,
            300,
            "approved test authorization",
            false);

        if (isPublic)
        {
            scope.ConfigureWebHosting(WebHostingMode.Public);
            publicAuthorization = new PublicTargetAuthorization(tenant.Id, "https://example.test/", Guid.NewGuid(), "Phase 4 acceptance test");
            publicAuthorization.Approve(Guid.NewGuid(), "approved ticket", "manual review", now.AddDays(5));
            scope.ConfigureVerifications([publicAuthorization.ToVerification()]);
        }
        else
        {
            scope.ConfigureWebHosting(WebHostingMode.Private, "worker-a", ["10.0.0.0/8"]);
            worker = new WorkerRegistration(tenant.Id, "worker-a", "test", ["web-assessment", "private-web-assessment"]);
            worker.ProvisionByAdministrator("test", ["web-assessment", "private-web-assessment"], ["10.0.0.0/8"]);
            worker.Heartbeat(0, 1);
        }

        // The initial occurrence is already due, while the authorization remains valid.
        var createdAt = now.AddHours(-25);
        var schedule = new AssessmentSchedule(
            tenant.Id,
            scope.Id,
            creatorId,
            WebAssessmentOperationProfiles.Passive,
            scope.GetAuthorizationFingerprint(),
            24,
            now.AddDays(5),
            createdAt);

        await using (var seed = new AppDbContext(options))
        {
            seed.Add(tenant);
            seed.Add(creator);
            seed.Add(scope);
            seed.Add(schedule);
            if (publicAuthorization is not null) seed.Add(publicAuthorization);
            if (worker is not null) seed.Add(worker);
            await seed.SaveChangesAsync();
        }

        await using (var mutate = new AppDbContext(options))
        {
            switch (scenario)
            {
                case "scope-mutated":
                    scope = await mutate.TargetScopes.SingleAsync(x => x.Id == scope.Id);
                    scope.Configure(
                        [new TargetDefinition(TargetKind.Web, "https://10.1.2.4/")],
                        scope.Exclusions,
                        scope.ApprovedOperationProfiles,
                        scope.RequestsPerMinute,
                        scope.MaxExecutionSeconds,
                        scope.AuthorizationEvidence,
                        false);
                    break;
                case "scope-expired":
                    scope = await mutate.TargetScopes.SingleAsync(x => x.Id == scope.Id);
                    scope.ExpireAuthorization();
                    break;
                case "public-authorization-revoked":
                    publicAuthorization = await mutate.PublicTargetAuthorizations.SingleAsync(x => x.Id == publicAuthorization!.Id);
                    publicAuthorization.Revoke();
                    break;
                case "worker-missing":
                    worker = await mutate.Workers.SingleAsync(x => x.Identity == "worker-a");
                    mutate.Workers.Remove(worker);
                    break;
                case "worker-disabled":
                    worker = await mutate.Workers.SingleAsync(x => x.Identity == "worker-a");
                    mutate.Entry(worker).Property(x => x.Status).CurrentValue = WorkerStatus.Disabled;
                    break;
                case "worker-unhealthy":
                    worker = await mutate.Workers.SingleAsync(x => x.Identity == "worker-a");
                    worker.MarkUnhealthy();
                    break;
                case "worker-stale":
                    worker = await mutate.Workers.SingleAsync(x => x.Identity == "worker-a");
                    mutate.Entry(worker).Property(x => x.LastHeartbeatAt).CurrentValue = now.AddMinutes(-5);
                    break;
                case "worker-capability-removed":
                    worker = await mutate.Workers.SingleAsync(x => x.Identity == "worker-a");
                    worker.ProvisionByAdministrator("test", ["web-assessment"], []);
                    break;
                case "worker-range-changed":
                    worker = await mutate.Workers.SingleAsync(x => x.Identity == "worker-a");
                    worker.ProvisionByAdministrator("test", ["web-assessment", "private-web-assessment"], ["192.168.0.0/16"]);
                    break;
                case "creator-deleted":
                    creator = await mutate.Users.SingleAsync(x => x.Id == creatorId);
                    mutate.Users.Remove(creator);
                    break;
                case "creator-role-downgraded":
                    creator = await mutate.Users.SingleAsync(x => x.Id == creatorId);
                    creator.SyncAuthenticatedIdentity("schedule-creator", "Schedule creator", UserRole.Viewer);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(scenario), scenario, "Unknown acceptance scenario.");
            }

            await mutate.SaveChangesAsync();
        }

        var processor = CreateProcessor(options);
        await processor.RunOnceAsync();

        await using var verify = new AppDbContext(options);
        var actualSchedule = await verify.AssessmentSchedules.SingleAsync(x => x.Id == schedule.Id);
        var run = await verify.AssessmentScheduleRuns.SingleAsync(x => x.ScheduleId == schedule.Id);

        Assert.Equal(AssessmentScheduleStatus.Blocked, actualSchedule.Status);
        Assert.False(string.IsNullOrWhiteSpace(actualSchedule.BlockedReason));
        Assert.Equal(AssessmentScheduleRunStatus.Blocked, run.Status);
        Assert.False(string.IsNullOrWhiteSpace(run.BlockedReason));
        Assert.Empty(await verify.AgentJobs.ToListAsync());
        Assert.Empty(await verify.AgentExecutions.ToListAsync());
        Assert.Empty(await verify.WebAssessments.ToListAsync());
        Assert.Empty(await verify.OutboxMessages.ToListAsync());
    }

    [Fact]
    public async Task Valid_due_occurrence_writes_one_run_job_assessment_and_outbox_and_retry_is_idempotent()
    {
        var options = NewOptions();
        var seed = await SeedValidPrivateScheduleAsync(options);
        var processor = CreateProcessor(options);

        await processor.RunOnceAsync();
        await processor.RunOnceAsync();

        await using var verify = new AppDbContext(options);
        var run = await verify.AssessmentScheduleRuns.SingleAsync(x => x.ScheduleId == seed.Schedule.Id);
        Assert.Equal(AssessmentScheduleRunStatus.Queued, run.Status);
        Assert.NotNull(run.JobId);
        Assert.NotNull(run.AssessmentId);
        Assert.Equal(1, await verify.AgentJobs.CountAsync());
        Assert.Equal(1, await verify.AgentExecutions.CountAsync());
        Assert.Equal(1, await verify.WebAssessments.CountAsync());
        Assert.Equal(1, await verify.OutboxMessages.CountAsync());
        Assert.Equal(AssessmentScheduleStatus.Active,
            (await verify.AssessmentSchedules.SingleAsync(x => x.Id == seed.Schedule.Id)).Status);
    }

    [Fact]
    public async Task Drift_notifications_are_tenant_isolated_private_and_acknowledgement_marks_notification_read()
    {
        var options = NewOptions();
        var tenantA = new Tenant("Drift tenant A");
        var tenantB = new Tenant("Drift tenant B");
        var creatorId = Guid.NewGuid();
        var scope = new TargetScope(tenantA.Id, "scope-a", creatorId, DateTimeOffset.UtcNow.AddDays(2));
        scope.Configure([new TargetDefinition(TargetKind.Web, "https://example.test/")], [],
            [WebAssessmentOperationProfiles.Passive], 30, 300, "approved", false);
        scope.ConfigureWebHosting(WebHostingMode.Private, "worker-a", ["10.0.0.0/8"]);
        var schedule = new AssessmentSchedule(tenantA.Id, scope.Id, creatorId,
            WebAssessmentOperationProfiles.Passive, scope.GetAuthorizationFingerprint(), 24,
            DateTimeOffset.UtcNow.AddDays(2), DateTimeOffset.UtcNow.AddHours(-1));
        var run = new AssessmentScheduleRun(tenantA.Id, schedule.Id, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow);
        var previousAssessmentId = Guid.NewGuid();
        var currentAssessmentId = Guid.NewGuid();
        var finding = new Finding(tenantA.Id, null, "credential-secret-marker", FindingSeverity.High);
        finding.ConfigureAssessmentDetails(currentAssessmentId, "security-headers", "High",
            "https://user:password@example.test/path?token=query-secret#fragment-secret",
            "GET", "token-secret", "raw-evidence-secret", "impact-secret", "screenshot-secret",
            "remediation-secret", null, WebCheckStatus.FindingDetected);
        var changes = AssessmentDriftComparer.Compare([], [], [finding], []);
        var change = Assert.Single(changes);
        var driftEvent = new AssessmentDriftEvent(tenantA.Id, schedule.Id, run.Id,
            previousAssessmentId, currentAssessmentId, change.EventType, change.StableIdentifier,
            change.PreviousSeverity, change.CurrentSeverity, change.Summary, DateTimeOffset.UtcNow);
        var notification = new Notification(tenantA.Id, "in-app",
            $"Scheduled assessment drift: {change.EventType}. Review the event in the SentinelAI Schedules workspace.",
            driftEvent.Id);

        await using (var seed = new AppDbContext(options))
        {
            seed.AddRange(tenantA, tenantB, scope, schedule, run, driftEvent, notification);
            await seed.SaveChangesAsync();
        }

        await using var db = new AppDbContext(options);
        var service = new AssessmentScheduleService(db, new AcceptingScopeValidator());
        var tenantAReader = new PrincipalContext(tenantA.Id, Guid.NewGuid(), "tenant-a-reader", UserRole.Viewer);
        var tenantBReader = new PrincipalContext(tenantB.Id, Guid.NewGuid(), "tenant-b-reader", UserRole.Viewer);
        var tenantAEvents = await service.ListDriftEventsAsync(tenantAReader, CancellationToken.None);
        var tenantANotifications = await service.ListNotificationsAsync(tenantAReader, CancellationToken.None);
        var tenantBEvents = await service.ListDriftEventsAsync(tenantBReader, CancellationToken.None);
        var tenantBNotifications = await service.ListNotificationsAsync(tenantBReader, CancellationToken.None);

        Assert.Contains(tenantAEvents, x => x.Id == driftEvent.Id);
        Assert.Contains(tenantANotifications, x => x.ResourceId == driftEvent.Id);
        Assert.Empty(tenantBEvents);
        Assert.Empty(tenantBNotifications);
        Assert.False(await service.AcknowledgeAsync(tenantBReader with { Role = UserRole.SecurityAnalyst }, driftEvent.Id, CancellationToken.None));

        var tenantAOperator = tenantAReader with { Role = UserRole.SecurityAnalyst };
        Assert.True(await service.AcknowledgeAsync(tenantAOperator, driftEvent.Id, CancellationToken.None));
        var savedNotification = await db.Notifications.SingleAsync(x => x.Id == notification.Id);
        Assert.True(savedNotification.IsRead);

        foreach (var response in tenantAEvents)
        {
            Assert.DoesNotContain("raw-evidence-secret", response.Summary, StringComparison.Ordinal);
            Assert.DoesNotContain("query-secret", response.Summary, StringComparison.Ordinal);
            Assert.DoesNotContain("fragment-secret", response.Summary, StringComparison.Ordinal);
            Assert.DoesNotContain("screenshot-secret", response.Summary, StringComparison.Ordinal);
            Assert.DoesNotContain("password", response.Summary, StringComparison.OrdinalIgnoreCase);
        }
        foreach (var response in tenantANotifications)
        {
            Assert.DoesNotContain("raw-evidence-secret", response.Message, StringComparison.Ordinal);
            Assert.DoesNotContain("query-secret", response.Message, StringComparison.Ordinal);
            Assert.DoesNotContain("fragment-secret", response.Message, StringComparison.Ordinal);
            Assert.DoesNotContain("screenshot-secret", response.Message, StringComparison.Ordinal);
        }
    }

    private static DbContextOptions<AppDbContext> NewOptions()
        => new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N"))
            .Options;

    private static AssessmentScheduleProcessor CreateProcessor(DbContextOptions<AppDbContext> options)
        => new(new ContextFactory(options), new AcceptingScopeValidator(), new EmptyQueue(),
            NullLogger<AssessmentScheduleProcessor>.Instance);

    private static async Task<SeededSchedule> SeedValidPrivateScheduleAsync(DbContextOptions<AppDbContext> options)
    {
        var now = DateTimeOffset.UtcNow;
        var tenant = new Tenant("Phase 4 valid schedule");
        var creatorId = Guid.NewGuid();
        var creator = new User(creatorId, tenant.Id, "creator", "Creator", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "bounded-web-scope", creatorId, now.AddDays(6));
        scope.Configure([new TargetDefinition(TargetKind.Web, "https://10.1.2.3/")], [],
            [WebAssessmentOperationProfiles.Passive], 30, 300, "approved test authorization", false);
        scope.ConfigureWebHosting(WebHostingMode.Private, "worker-a", ["10.0.0.0/8"]);
        var worker = new WorkerRegistration(tenant.Id, "worker-a", "test", ["web-assessment", "private-web-assessment"]);
        worker.ProvisionByAdministrator("test", ["web-assessment", "private-web-assessment"], ["10.0.0.0/8"]);
        worker.Heartbeat(0, 1);
        var createdAt = now.AddHours(-25);
        var schedule = new AssessmentSchedule(tenant.Id, scope.Id, creatorId, WebAssessmentOperationProfiles.Passive,
            scope.GetAuthorizationFingerprint(), 24, now.AddDays(5), createdAt);
        await using var db = new AppDbContext(options);
        db.AddRange(tenant, creator, scope, worker, schedule);
        await db.SaveChangesAsync();
        return new SeededSchedule(schedule, tenant, scope, worker, creator);
    }

    private sealed record SeededSchedule(AssessmentSchedule Schedule, Tenant Tenant, TargetScope Scope,
        WorkerRegistration Worker, User Creator);

    private sealed class ContextFactory(DbContextOptions<AppDbContext> options) : IAppDbContextFactory
    {
        public IAppDbContext CreateDbContext() => new AppDbContext(options);
    }

    private sealed class AcceptingScopeValidator : ITargetScopeValidator
    {
        public ScopeValidationResult ValidateDefinition(TargetScope scope, Guid tenantId, DateTimeOffset now)
            => ScopeValidationResult.Valid();

        public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId,
            string target, string operationProfile, CancellationToken cancellationToken = default)
            => ValidateExecutionAsync(scope, tenantId, TargetKind.Web, target, operationProfile, null, cancellationToken);

        public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId,
            TargetKind kind, string target, string operationProfile, CancellationToken cancellationToken = default)
            => ValidateExecutionAsync(scope, tenantId, kind, target, operationProfile, null, cancellationToken);

        public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId,
            TargetKind kind, string target, string operationProfile, WorkerExecutionContext? worker,
            CancellationToken cancellationToken = default)
        {
            if (!Uri.TryCreate(target, UriKind.Absolute, out var uri))
                return ValueTask.FromResult(ScopeValidationResult.Invalid(["Test target must be an absolute URI."]));
            return ValueTask.FromResult(ScopeValidationResult.Valid(new ValidatedExecutionTarget(
                uri.Host, [IPAddress.Loopback], DateTimeOffset.UtcNow, scope.Id, tenantId,
                scope.ExpiresAt, operationProfile)));
        }

        public ValueTask<ScopeValidationResult> ValidateRedirectAsync(TargetScope scope, Guid tenantId,
            Uri redirect, string operationProfile, CancellationToken cancellationToken = default)
            => ValidateExecutionAsync(scope, tenantId, TargetKind.Web, redirect.ToString(), operationProfile, cancellationToken);
    }

    private sealed class EmptyQueue : IScanJobQueue
    {
        public ValueTask EnqueueAsync(Guid jobId, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;
        public ValueTask EnqueueAsync(Guid jobId, Guid tenantId, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;
        public IAsyncEnumerable<ScanJobDelivery> ReadAllAsync(Guid? tenantId = null, string? workerIdentity = null,
            CancellationToken cancellationToken = default) => EmptyAsync<ScanJobDelivery>();
        public ValueTask RequestCancellationAsync(Guid jobId, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;
        public ValueTask RequestCancellationAsync(Guid jobId, Guid tenantId, string workerIdentity,
            CancellationToken cancellationToken = default) => ValueTask.CompletedTask;
        public IAsyncEnumerable<Guid> ReadCancellationsAsync(Guid tenantId, string workerIdentity,
            CancellationToken cancellationToken = default) => EmptyAsync<Guid>();

        private static async IAsyncEnumerable<T> EmptyAsync<T>([EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.CompletedTask;
            yield break;
        }
    }
}
