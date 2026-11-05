using System.Net;
using System.Runtime.CompilerServices;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application;
using SentinelAI.Contracts;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;
using SentinelAI.Security.Policy;

namespace SentinelAI.UnitTests;

public sealed class AssessmentScheduleProcessorAcceptanceTests
{
    [Theory]
    [InlineData(24, WebAssessmentOperationProfiles.Passive)]
    [InlineData(2160, WebAssessmentOperationProfiles.Passive)]
    [InlineData(24, WebAssessmentOperationProfiles.SafeActive)]
    public async Task Schedule_creation_accepts_bounded_interval_and_each_supported_profile(int intervalHours, string operationProfile)
    {
        var options = NewOptions();
        var now = DateTimeOffset.UtcNow;
        var tenant = new Tenant("Phase 4 interval boundary tenant");
        var creatorId = Guid.NewGuid();
        var creator = new User(creatorId, tenant.Id, "interval-creator", "Interval creator", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "interval-boundary-scope", creatorId, now.AddDays(100));
        scope.Configure([new TargetDefinition(TargetKind.Web, "https://10.3.4.5/")], [],
            [operationProfile], 30, 300, "approved interval-boundary authorization", false);
        scope.ConfigureWebHosting(WebHostingMode.Private, "interval-worker", ["10.0.0.0/8"]);
        var worker = new WorkerRegistration(tenant.Id, "interval-worker", "test",
            ["web-assessment", "private-web-assessment"]);
        worker.ProvisionByAdministrator("test", ["web-assessment", "private-web-assessment"], ["10.0.0.0/8"]);
        worker.Heartbeat(0, 1);

        await using var db = new AppDbContext(options);
        db.AddRange(tenant, creator, scope, worker);
        await db.SaveChangesAsync();

        var service = new AssessmentScheduleService(db, new AcceptingScopeValidator());
        var principal = new PrincipalContext(tenant.Id, creatorId, creator.Subject, UserRole.SecurityAnalyst);
        var endsAt = now.AddHours(intervalHours + 24);
        var result = await service.CreateAsync(principal,
            new CreateAssessmentScheduleRequest(scope.Id, operationProfile, intervalHours, endsAt),
            CancellationToken.None);

        Assert.Equal(intervalHours, result.IntervalHours);
        Assert.Equal(operationProfile, result.OperationProfile);
        Assert.Equal(AssessmentScheduleStatus.Active, result.Status);
        Assert.NotNull(result.NextRunAt);
        Assert.Equal(scope.Id, result.ScopeId);
    }

    [Theory]
    [InlineData(23)]
    [InlineData(2161)]
    public async Task Schedule_creation_rejects_intervals_outside_the_24_hour_to_90_day_bounds(int intervalHours)
    {
        await using var db = new AppDbContext(NewOptions());
        var service = new AssessmentScheduleService(db, new AcceptingScopeValidator());
        var principal = new PrincipalContext(Guid.NewGuid(), Guid.NewGuid(), "invalid-interval-operator",
            UserRole.SecurityAnalyst);

        await Assert.ThrowsAsync<ScopeValidationException>(() => service.CreateAsync(principal,
            new CreateAssessmentScheduleRequest(Guid.NewGuid(), WebAssessmentOperationProfiles.Passive,
                intervalHours, DateTimeOffset.UtcNow.AddDays(100)),
            CancellationToken.None));
    }

    [Theory]
    [InlineData("network-discovery")]
    [InlineData("arbitrary-ai-command")]
    public async Task Schedule_creation_rejects_profiles_outside_the_supported_allowlist(string operationProfile)
    {
        await using var db = new AppDbContext(NewOptions());
        var service = new AssessmentScheduleService(db, new AcceptingScopeValidator());
        var principal = new PrincipalContext(Guid.NewGuid(), Guid.NewGuid(), "unsupported-profile-operator",
            UserRole.SecurityAnalyst);

        await Assert.ThrowsAsync<ScopeValidationException>(() => service.CreateAsync(principal,
            new CreateAssessmentScheduleRequest(Guid.NewGuid(), operationProfile, 24,
                DateTimeOffset.UtcNow.AddHours(48)),
            CancellationToken.None));
    }

    [Fact]
    public async Task Schedule_creation_rejects_a_supported_profile_not_approved_by_the_original_scope()
    {
        var options = NewOptions();
        var seed = await SeedValidPrivateScheduleAsync(options);

        await using (var updateScope = new AppDbContext(options))
        {
            var scope = await updateScope.TargetScopes.SingleAsync(x => x.Id == seed.Scope.Id);
            scope.Configure(scope.Targets, scope.Exclusions, [WebAssessmentOperationProfiles.Passive],
                scope.RequestsPerMinute, scope.MaxExecutionSeconds, scope.AuthorizationEvidence, false);
            await updateScope.SaveChangesAsync();
        }

        await using var db = new AppDbContext(options);
        var service = new AssessmentScheduleService(db, new AcceptingScopeValidator());
        var principal = new PrincipalContext(seed.Tenant.Id, seed.Creator.Id, seed.Creator.Subject,
            UserRole.SecurityAnalyst);

        await Assert.ThrowsAsync<ScopeValidationException>(() => service.CreateAsync(principal,
            new CreateAssessmentScheduleRequest(seed.Scope.Id, WebAssessmentOperationProfiles.SafeActive, 24,
                DateTimeOffset.UtcNow.AddHours(48)),
            CancellationToken.None));
    }

    [Fact]
    public async Task Schedule_creation_rejects_an_end_time_that_does_not_allow_one_complete_interval()
    {
        await using var db = new AppDbContext(NewOptions());
        var service = new AssessmentScheduleService(db, new AcceptingScopeValidator());
        var principal = new PrincipalContext(Guid.NewGuid(), Guid.NewGuid(), "short-schedule-operator",
            UserRole.SecurityAnalyst);

        await Assert.ThrowsAsync<ScopeValidationException>(() => service.CreateAsync(principal,
            new CreateAssessmentScheduleRequest(Guid.NewGuid(), WebAssessmentOperationProfiles.Passive,
                24, DateTimeOffset.UtcNow.AddHours(23)),
            CancellationToken.None));
    }

    [Theory]
    [InlineData("scope-mutated")]
    [InlineData("scope-expired")]
    [InlineData("public-authorization-revoked")]
    [InlineData("public-authorization-expired")]
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
        var isPublic = scenario is "public-authorization-revoked" or "public-authorization-expired";
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
                case "public-authorization-expired":
                    publicAuthorization = await mutate.PublicTargetAuthorizations.SingleAsync(x => x.Id == publicAuthorization!.Id);
                    mutate.Entry(publicAuthorization).Property(x => x.ExpiresAt).CurrentValue = now.AddSeconds(-1);
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
    public async Task Failed_due_cycle_retries_without_losing_or_duplicating_the_scheduled_occurrence()
    {
        var options = NewOptions();
        var seed = await SeedValidPrivateScheduleAsync(options);
        var validator = new TransientScopeValidator();
        var processor = CreateProcessor(options, validator);

        await processor.RunOnceAsync();
        await using (var afterFailure = new AppDbContext(options))
        {
            Assert.Empty(await afterFailure.AssessmentScheduleRuns.ToListAsync());
            Assert.Empty(await afterFailure.AgentJobs.ToListAsync());
            Assert.Empty(await afterFailure.OutboxMessages.ToListAsync());
            Assert.Equal(AssessmentScheduleStatus.Active,
                (await afterFailure.AssessmentSchedules.SingleAsync(x => x.Id == seed.Schedule.Id)).Status);
        }

        await processor.RunOnceAsync();

        await using var verify = new AppDbContext(options);
        Assert.Equal(2, validator.ValidationAttempts);
        Assert.Single(await verify.AssessmentScheduleRuns.Where(x => x.ScheduleId == seed.Schedule.Id).ToListAsync());
        Assert.Single(await verify.AgentJobs.ToListAsync());
        Assert.Single(await verify.WebAssessments.ToListAsync());
        Assert.Single(await verify.OutboxMessages.ToListAsync());
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
        Assert.Contains(tenantANotifications, x => x.EventId == driftEvent.Id);
        Assert.Empty(tenantBEvents);
        Assert.Empty(tenantBNotifications);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            service.AcknowledgeAsync(tenantAReader, driftEvent.Id, CancellationToken.None));
        Assert.False(await service.AcknowledgeAsync(tenantBReader with { Role = UserRole.SecurityAnalyst },
            driftEvent.Id, CancellationToken.None));

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

    private static AssessmentScheduleProcessor CreateProcessor(DbContextOptions<AppDbContext> options, ITargetScopeValidator? validator = null)
        => new(new ContextFactory(options), validator ?? new AcceptingScopeValidator(), new EmptyQueue(),
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

    private sealed class TransientScopeValidator : ITargetScopeValidator
    {
        private readonly AcceptingScopeValidator inner = new();
        private int attempts;
        public int ValidationAttempts => Volatile.Read(ref attempts);

        public ScopeValidationResult ValidateDefinition(TargetScope scope, Guid tenantId, DateTimeOffset now)
        {
            if (Interlocked.Increment(ref attempts) == 1)
                throw new InvalidOperationException("Simulated transient authorization-store failure.");
            return inner.ValidateDefinition(scope, tenantId, now);
        }

        public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId,
            string target, string operationProfile, CancellationToken cancellationToken = default)
            => inner.ValidateExecutionAsync(scope, tenantId, target, operationProfile, cancellationToken);

        public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId,
            TargetKind kind, string target, string operationProfile, CancellationToken cancellationToken = default)
            => inner.ValidateExecutionAsync(scope, tenantId, kind, target, operationProfile, cancellationToken);

        public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId,
            TargetKind kind, string target, string operationProfile, WorkerExecutionContext? worker,
            CancellationToken cancellationToken = default)
            => inner.ValidateExecutionAsync(scope, tenantId, kind, target, operationProfile, worker, cancellationToken);

        public ValueTask<ScopeValidationResult> ValidateRedirectAsync(TargetScope scope, Guid tenantId,
            Uri redirect, string operationProfile, CancellationToken cancellationToken = default)
            => inner.ValidateRedirectAsync(scope, tenantId, redirect, operationProfile, cancellationToken);
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
            var uri = new Uri(target, UriKind.Absolute);
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
