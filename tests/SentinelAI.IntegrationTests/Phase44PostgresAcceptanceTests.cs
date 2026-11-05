using System.Data;
using System.Net;
using System.Runtime.CompilerServices;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SentinelAI.Application;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;
using SentinelAI.Security.Policy;

namespace SentinelAI.IntegrationTests;

public sealed class Phase44PostgresAcceptanceTests
{
    private const string Phase44MigrationId = "20261104130000_Phase44ScheduledReassessment";

    [Fact]
    public async Task Phase44_migration_upgrades_rolls_back_and_reapplies_on_postgresql()
    {
        var connectionString = Environment.GetEnvironmentVariable("SENTINELAI_POSTGRES_CONNECTION");
        Assert.False(string.IsNullOrWhiteSpace(connectionString),
            "CI must provide SENTINELAI_POSTGRES_CONNECTION so Phase 4 migration acceptance is exercised against PostgreSQL.");

        var schema = $"phase44_upgrade_{Guid.NewGuid():N}";
        await CreateSchemaAsync(connectionString!, schema);
        try
        {
            var schemaConnectionString = WithSearchPath(connectionString!, schema);
            var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(schemaConnectionString).Options;
            var migrations = new List<string>();
            await using (var db = new AppDbContext(options))
            {
                migrations = db.Database.GetMigrations().ToList();
                var phaseIndex = migrations.IndexOf(Phase44MigrationId);
                Assert.True(phaseIndex > 0, $"Expected {Phase44MigrationId} to have a previous released migration.");
                var previousMigration = migrations[phaseIndex - 1];

                await db.Database.MigrateAsync(previousMigration);
                Assert.False(await ObjectExistsAsync(schemaConnectionString, "table", "AssessmentSchedules"));
                Assert.False(await ObjectExistsAsync(schemaConnectionString, "column", "ResourceId"));

                await db.Database.MigrateAsync(Phase44MigrationId);
                Assert.True(await ObjectExistsAsync(schemaConnectionString, "table", "AssessmentSchedules"));
                Assert.True(await ObjectExistsAsync(schemaConnectionString, "table", "AssessmentScheduleRuns"));
                Assert.True(await ObjectExistsAsync(schemaConnectionString, "table", "AssessmentDriftEvents"));
                Assert.True(await ObjectExistsAsync(schemaConnectionString, "column", "ResourceId"));
                Assert.True(await ObjectExistsAsync(schemaConnectionString, "index", "IX_AssessmentScheduleRuns_TenantId_ScheduleId_ScheduledFor"));
                Assert.True(await ObjectExistsAsync(schemaConnectionString, "index",
                    "IX_AssessmentDriftEvents_TenantId_ScheduleRunId_EventType_StableIdentifier"[..63]));
                Assert.True(await ObjectExistsAsync(schemaConnectionString, "constraint", "FK_AssessmentSchedules_TargetScopes_TenantId_ScopeId"));
                Assert.True(await ObjectExistsAsync(schemaConnectionString, "constraint", "FK_Notifications_AssessmentDriftEvents_TenantId_ResourceId"));

                // Exercise the actual Down migration, then upgrade again to prove a clean recovery path.
                await db.Database.MigrateAsync(previousMigration);
                Assert.False(await ObjectExistsAsync(schemaConnectionString, "table", "AssessmentSchedules"));
                Assert.False(await ObjectExistsAsync(schemaConnectionString, "table", "AssessmentScheduleRuns"));
                Assert.False(await ObjectExistsAsync(schemaConnectionString, "table", "AssessmentDriftEvents"));
                Assert.False(await ObjectExistsAsync(schemaConnectionString, "column", "ResourceId"));
                Assert.True(await ObjectExistsAsync(schemaConnectionString, "table", "TargetScopes"));

                await db.Database.MigrateAsync(Phase44MigrationId);
                Assert.True(await ObjectExistsAsync(schemaConnectionString, "table", "AssessmentSchedules"));
                Assert.True(await ObjectExistsAsync(schemaConnectionString, "table", "AssessmentDriftEvents"));
                Assert.True(await ObjectExistsAsync(schemaConnectionString, "index", "IX_Notifications_TenantId_Channel_ResourceId"));
            }
        }
        finally
        {
            await DropSchemaAsync(connectionString!, schema);
        }
    }

    [Fact]
    public async Task Scope_authorization_fingerprint_is_stable_after_postgresql_round_trip()
    {
        var connectionString = Environment.GetEnvironmentVariable("SENTINELAI_POSTGRES_CONNECTION");
        Assert.False(string.IsNullOrWhiteSpace(connectionString),
            "CI must provide SENTINELAI_POSTGRES_CONNECTION so timestamp precision is verified against PostgreSQL.");

        var schema = $"phase44_fingerprint_{Guid.NewGuid():N}";
        await CreateSchemaAsync(connectionString!, schema);
        try
        {
            var schemaConnectionString = WithSearchPath(connectionString!, schema);
            var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(schemaConnectionString).Options;
            await using (var migrate = new AppDbContext(options))
                await migrate.Database.MigrateAsync();

            var now = DateTimeOffset.UtcNow;
            var tenant = new Tenant("Phase 4 fingerprint tenant");
            var adminId = Guid.NewGuid();
            var admin = new User(adminId, tenant.Id, "phase4-fingerprint-admin", "Phase 4 admin", UserRole.Admin);
            var scope = new TargetScope(tenant.Id, "phase4-fingerprint-scope", adminId, now.AddDays(20).AddTicks(7));
            scope.Configure([new TargetDefinition(TargetKind.Web, "https://example.test/")], [],
                [WebAssessmentOperationProfiles.Passive], 30, 300, "approved fingerprint-test authorization", false);
            var authorization = new PublicTargetAuthorization(tenant.Id, "https://example.test/", adminId,
                "Phase 4 PostgreSQL fingerprint acceptance");
            authorization.Approve(Guid.NewGuid(), "ticket-fingerprint-1", "manual verification",
                now.AddDays(10).AddTicks(3), allowRequesterApproval: true);
            scope.ConfigureVerifications([authorization.ToVerification()]);

            await using (var seed = new AppDbContext(options))
            {
                seed.AddRange(tenant, admin, scope, authorization);
                await seed.SaveChangesAsync();
            }

            // The application creates schedules from a scope loaded from PostgreSQL, not from
            // an unsaved in-memory object. Fingerprint stability is required after that point.
            string expected;
            await using (var firstRead = new AppDbContext(options))
            {
                var persistedScope = await firstRead.TargetScopes.AsNoTracking()
                    .SingleAsync(x => x.Id == scope.Id);
                expected = persistedScope.GetAuthorizationFingerprint();
            }

            await using var verify = new AppDbContext(options);
            var reloadedScope = await verify.TargetScopes.AsNoTracking().SingleAsync(x => x.Id == scope.Id);
            Assert.Equal(expected, reloadedScope.GetAuthorizationFingerprint());
        }
        finally
        {
            await DropSchemaAsync(connectionString!, schema);
        }
    }

    [Fact]
    public async Task Concurrent_scheduler_processors_create_exactly_one_due_occurrence_and_outbox_job()
    {
        var connectionString = Environment.GetEnvironmentVariable("SENTINELAI_POSTGRES_CONNECTION");
        Assert.False(string.IsNullOrWhiteSpace(connectionString),
            "CI must provide SENTINELAI_POSTGRES_CONNECTION so scheduler concurrency acceptance is exercised against PostgreSQL.");

        var schema = $"phase44_race_{Guid.NewGuid():N}";
        await CreateSchemaAsync(connectionString!, schema);
        try
        {
            var schemaConnectionString = WithSearchPath(connectionString!, schema);
            var options = new DbContextOptionsBuilder<AppDbContext>()
                .UseNpgsql(schemaConnectionString)
                .EnableDetailedErrors()
                .Options;
            await using (var migrate = new AppDbContext(options))
                await migrate.Database.MigrateAsync();

            var now = DateTimeOffset.UtcNow;
            var tenant = new Tenant("Phase 4 concurrent scheduler tenant");
            var creatorId = Guid.NewGuid();
            var creator = new User(creatorId, tenant.Id, "phase4-race-creator", "Phase 4 creator", UserRole.SecurityAnalyst);
            var scope = new TargetScope(tenant.Id, "phase4-race-scope", creatorId, now.AddDays(6));
            scope.Configure([new TargetDefinition(TargetKind.Web, "https://10.2.3.4/")], [],
                [WebAssessmentOperationProfiles.Passive], 30, 300, "approved race-test authorization", false);
            scope.ConfigureWebHosting(WebHostingMode.Private, "phase4-race-worker", ["10.0.0.0/8"]);
            var worker = new WorkerRegistration(tenant.Id, "phase4-race-worker", "test",
                ["web-assessment", "private-web-assessment"]);
            worker.ProvisionByAdministrator("test",
                ["web-assessment", "private-web-assessment"], ["10.0.0.0/8"]);
            worker.Heartbeat(0, 2);

            await using (var seed = new AppDbContext(options))
            {
                seed.AddRange(tenant, creator, scope, worker);
                await seed.SaveChangesAsync();
            }

            // Match the production service: schedule creation reads the already-persisted scope.
            string persistedFingerprint;
            await using (var scopeRead = new AppDbContext(options))
            {
                var persistedScope = await scopeRead.TargetScopes.AsNoTracking()
                    .SingleAsync(x => x.Id == scope.Id);
                persistedFingerprint = persistedScope.GetAuthorizationFingerprint();
            }

            var schedule = new AssessmentSchedule(tenant.Id, scope.Id, creatorId,
                WebAssessmentOperationProfiles.Passive, persistedFingerprint,
                24, now.AddDays(5), now.AddHours(-25));
            await using (var seedSchedule = new AppDbContext(options))
            {
                seedSchedule.AssessmentSchedules.Add(schedule);
                await seedSchedule.SaveChangesAsync();
            }

            await using (var fingerprintCheck = new AppDbContext(options))
            {
                var persistedScope = await fingerprintCheck.TargetScopes.AsNoTracking()
                    .SingleAsync(x => x.Id == scope.Id);
                Assert.Equal(schedule.AuthorizationFingerprint, persistedScope.GetAuthorizationFingerprint());
            }

            var processors = Enumerable.Range(0, 8).Select(_ => CreateProcessor(options)).ToArray();
            await Task.WhenAll(processors.Select(processor => processor.RunOnceAsync(batchSize: 20)));
            // Subsequent cycles simulate recovery/retry after multiple scheduler instances observed the same work.
            await Task.WhenAll(processors.Select(processor => processor.RunOnceAsync(batchSize: 20)));

            await using var verify = new AppDbContext(options);
            var runs = await verify.AssessmentScheduleRuns.Where(x => x.TenantId == tenant.Id && x.ScheduleId == schedule.Id).ToListAsync();
            Assert.Single(runs);
            Assert.True(runs[0].Status == AssessmentScheduleRunStatus.Queued,
                $"Expected queued run, but got {runs[0].Status}. Run reason: {runs[0].BlockedReason ?? "none"}. Schedule reason: {(await verify.AssessmentSchedules.SingleAsync(x => x.Id == schedule.Id)).BlockedReason ?? "none"}.");
            Assert.NotNull(runs[0].JobId);
            Assert.NotNull(runs[0].AssessmentId);
            Assert.Equal(1, await verify.AgentJobs.CountAsync(x => x.TenantId == tenant.Id && x.ScopeId == scope.Id));
            Assert.Equal(1, await verify.AgentExecutions.CountAsync());
            Assert.Equal(1, await verify.WebAssessments.CountAsync(x => x.TenantId == tenant.Id && x.ScopeId == scope.Id));
            Assert.Equal(1, await verify.OutboxMessages.CountAsync(x => x.TenantId == tenant.Id));
        }
        finally
        {
            await DropSchemaAsync(connectionString!, schema);
        }
    }

    [Fact]
    public async Task Scheduled_outbox_is_dispatched_to_the_tenant_and_worker_bound_rabbitmq_queue()
    {
        var connectionString = Environment.GetEnvironmentVariable("SENTINELAI_POSTGRES_CONNECTION");
        Assert.False(string.IsNullOrWhiteSpace(connectionString),
            "CI must provide SENTINELAI_POSTGRES_CONNECTION for scheduled outbox dispatch acceptance.");

        var schema = $"phase44_rabbit_outbox_{Guid.NewGuid():N}";
        await CreateSchemaAsync(connectionString!, schema);
        try
        {
            var schemaConnectionString = WithSearchPath(connectionString!, schema);
            var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(schemaConnectionString).Options;
            await using (var migrate = new AppDbContext(options))
                await migrate.Database.MigrateAsync();

            var now = DateTimeOffset.UtcNow;
            var tenant = new Tenant("Phase 4 scheduled RabbitMQ outbox tenant");
            var creatorId = Guid.NewGuid();
            var creator = new User(creatorId, tenant.Id, "phase44-rabbit-creator",
                "Phase 4 RabbitMQ creator", UserRole.SecurityAnalyst);
            const string workerIdentity = "phase44-rabbit-worker";
            var scope = new TargetScope(tenant.Id, "phase44-rabbit-scope", creatorId, now.AddDays(6));
            scope.Configure([new TargetDefinition(TargetKind.Web, "https://10.8.9.10/")], [],
                [WebAssessmentOperationProfiles.Passive], 30, 300, "approved RabbitMQ outbox test authorization", false);
            scope.ConfigureWebHosting(WebHostingMode.Private, workerIdentity, ["10.0.0.0/8"]);
            var worker = new WorkerRegistration(tenant.Id, workerIdentity, "test",
                ["web-assessment", "private-web-assessment"]);
            worker.ProvisionByAdministrator("test",
                ["web-assessment", "private-web-assessment"], ["10.0.0.0/8"]);
            worker.Heartbeat(0, 1);

            await using (var seed = new AppDbContext(options))
            {
                seed.AddRange(tenant, creator, scope, worker);
                await seed.SaveChangesAsync();
            }

            string persistedFingerprint;
            await using (var scopeRead = new AppDbContext(options))
            {
                var persistedScope = await scopeRead.TargetScopes.AsNoTracking()
                    .SingleAsync(x => x.Id == scope.Id);
                persistedFingerprint = persistedScope.GetAuthorizationFingerprint();
            }

            var schedule = new AssessmentSchedule(tenant.Id, scope.Id, creatorId,
                WebAssessmentOperationProfiles.Passive, persistedFingerprint,
                24, now.AddDays(5), now.AddHours(-25));
            await using (var seedSchedule = new AppDbContext(options))
            {
                seedSchedule.AssessmentSchedules.Add(schedule);
                await seedSchedule.SaveChangesAsync();
            }

            // Generate the exact outbox record written by the real scheduled-assessment processor.
            await CreateProcessor(options).RunOnceAsync();

            Guid expectedJobId;
            await using (var verifyQueued = new AppDbContext(options))
            {
                var run = await verifyQueued.AssessmentScheduleRuns.SingleAsync(x => x.ScheduleId == schedule.Id);
                Assert.Equal(AssessmentScheduleRunStatus.Queued, run.Status);
                expectedJobId = Assert.IsType<Guid>(run.JobId);
                var outbox = await verifyQueued.OutboxMessages.SingleAsync(x => x.TenantId == tenant.Id);
                Assert.Equal(OutboxMessageTypes.ScanJob, outbox.MessageType);
                Assert.Null(outbox.DispatchedAt);
            }

            var rabbitConfiguration = new ConfigurationManager();
            rabbitConfiguration["RabbitMQ:Host"] = Environment.GetEnvironmentVariable("RABBITMQ_TEST_HOST") ?? "localhost";
            rabbitConfiguration["RabbitMQ:Port"] = Environment.GetEnvironmentVariable("RABBITMQ_TEST_PORT") ?? "5672";
            rabbitConfiguration["RabbitMQ:Username"] = Environment.GetEnvironmentVariable("RABBITMQ_TEST_USER") ?? "sentinelai";
            rabbitConfiguration["RabbitMQ:Password"] = Environment.GetEnvironmentVariable("RABBITMQ_TEST_PASSWORD") ?? "replace-with-local-dev-password";

            await using var rabbitProvider = new RabbitMqConnectionProvider(
                rabbitConfiguration, NullLogger<RabbitMqConnectionProvider>.Instance);
            var rabbitQueue = new RabbitMqScanJobQueue(
                rabbitProvider, rabbitConfiguration, NullLogger<RabbitMqScanJobQueue>.Instance);

            var dispatcherServices = new ServiceCollection();
            dispatcherServices.AddDbContext<AppDbContext>(builder => builder.UseNpgsql(schemaConnectionString));
            await using var dispatcherProvider = dispatcherServices.BuildServiceProvider();
            var dispatcher = new OutboxDispatcher(
                dispatcherProvider.GetRequiredService<IServiceScopeFactory>(),
                rabbitQueue,
                rabbitConfiguration,
                NullLogger<OutboxDispatcher>.Instance);

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await using var deliveryReader = rabbitQueue
                .ReadAllAsync(tenant.Id, workerIdentity, timeout.Token)
                .GetAsyncEnumerator(timeout.Token);
            var deliveryTask = deliveryReader.MoveNextAsync().AsTask();

            await dispatcher.StartAsync(CancellationToken.None);
            try
            {
                Assert.True(await deliveryTask.WaitAsync(TimeSpan.FromSeconds(15)),
                    "The scheduled outbox message was not delivered to the bound RabbitMQ worker queue.");
                var delivery = deliveryReader.Current;
                Assert.Equal(expectedJobId, delivery.JobId);
                Assert.Equal(tenant.Id, delivery.TenantId);
                Assert.Equal(workerIdentity, delivery.WorkerIdentity);
                await delivery.AcknowledgeAsync(timeout.Token);

                var dispatched = false;
                for (var attempt = 0; attempt < 50; attempt++)
                {
                    await using var verifyDispatch = new AppDbContext(options);
                    var outbox = await verifyDispatch.OutboxMessages.SingleAsync(x => x.TenantId == tenant.Id);
                    if (outbox.DispatchedAt is not null)
                    {
                        dispatched = true;
                        Assert.Null(outbox.LeaseExpiresAt);
                        break;
                    }
                    await Task.Delay(100, timeout.Token);
                }

                Assert.True(dispatched, "The real outbox dispatcher did not persist the dispatched state.");
            }
            finally
            {
                await dispatcher.StopAsync(CancellationToken.None);
            }
        }
        finally
        {
            await DropSchemaAsync(connectionString!, schema);
        }
    }

    [Fact]
    public async Task Concurrent_processors_reconcile_a_completed_scheduled_assessment_without_duplicate_drift_or_notifications()
    {
        var connectionString = Environment.GetEnvironmentVariable("SENTINELAI_POSTGRES_CONNECTION");
        Assert.False(string.IsNullOrWhiteSpace(connectionString),
            "CI must provide SENTINELAI_POSTGRES_CONNECTION so reconciliation concurrency is exercised against PostgreSQL.");

        var schema = $"phase44_reconcile_race_{Guid.NewGuid():N}";
        await CreateSchemaAsync(connectionString!, schema);
        try
        {
            var schemaConnectionString = WithSearchPath(connectionString!, schema);
            var options = new DbContextOptionsBuilder<AppDbContext>()
                .UseNpgsql(schemaConnectionString)
                .EnableDetailedErrors()
                .Options;
            await using (var migrate = new AppDbContext(options))
                await migrate.Database.MigrateAsync();

            var now = DateTimeOffset.UtcNow;
            var tenant = new Tenant("Phase 4 reconciliation concurrency tenant");
            var creatorId = Guid.NewGuid();
            var creator = new User(creatorId, tenant.Id, "phase4-reconcile-creator",
                "Phase 4 reconciliation creator", UserRole.SecurityAnalyst);
            var scope = new TargetScope(tenant.Id, "phase4-reconcile-scope", creatorId, now.AddDays(6));
            scope.Configure([new TargetDefinition(TargetKind.Web, "https://10.4.5.6/")], [],
                [WebAssessmentOperationProfiles.Passive], 30, 300, "approved reconciliation test authorization", false);
            scope.ConfigureWebHosting(WebHostingMode.Private, "phase4-reconcile-worker", ["10.0.0.0/8"]);
            var worker = new WorkerRegistration(tenant.Id, "phase4-reconcile-worker", "test",
                ["web-assessment", "private-web-assessment"]);
            worker.ProvisionByAdministrator("test",
                ["web-assessment", "private-web-assessment"], ["10.0.0.0/8"]);
            worker.Heartbeat(0, 2);

            var previousJob = new AgentJob(tenant.Id, scope.Id, creatorId, WebAssessmentOperationProfiles.Passive);
            var previousAssessment = new WebAssessment(tenant.Id, previousJob.Id, scope.Id,
                "https://10.4.5.6/", WebAssessmentOperationProfiles.Passive, WebHostingMode.Private);
            previousAssessment.Complete("previous-report", 0);
            var previousFinding = new Finding(tenant.Id, null, "Missing security headers", FindingSeverity.High);
            previousFinding.ConfigureAssessmentDetails(previousAssessment.Id, "security-headers", "High",
                "https://10.4.5.6/headers", "GET", null, "Previous finding", "impact", null, "fix", null,
                WebCheckStatus.FindingDetected);
            var previousCheck = new WebAssessmentCheck(tenant.Id, previousAssessment.Id,
                "security-headers", "Security headers", "security-headers", WebCheckStatus.FindingDetected,
                "https://10.4.5.6/headers");

            await using (var seed = new AppDbContext(options))
            {
                seed.AddRange(tenant, creator, scope, worker, previousJob, previousAssessment,
                    previousFinding, previousCheck);
                await seed.SaveChangesAsync();
            }

            string persistedFingerprint;
            await using (var scopeRead = new AppDbContext(options))
            {
                var persistedScope = await scopeRead.TargetScopes.AsNoTracking()
                    .SingleAsync(x => x.Id == scope.Id);
                persistedFingerprint = persistedScope.GetAuthorizationFingerprint();
            }

            var schedule = new AssessmentSchedule(tenant.Id, scope.Id, creatorId,
                WebAssessmentOperationProfiles.Passive, persistedFingerprint,
                24, now.AddDays(5), now.AddHours(-25));
            await using (var seedSchedule = new AppDbContext(options))
            {
                seedSchedule.AssessmentSchedules.Add(schedule);
                await seedSchedule.SaveChangesAsync();
            }

            var processors = Enumerable.Range(0, 8).Select(_ => CreateProcessor(options)).ToArray();
            await processors[0].RunOnceAsync();

            await using (var completeCurrent = new AppDbContext(options))
            {
                var run = await completeCurrent.AssessmentScheduleRuns.SingleAsync(x => x.ScheduleId == schedule.Id);
                Assert.NotNull(run.AssessmentId);
                var currentAssessment = await completeCurrent.WebAssessments.SingleAsync(x => x.Id == run.AssessmentId);
                currentAssessment.Complete("current-report", 0);

                var newFinding = new Finding(tenant.Id, null, "New reflected input", FindingSeverity.High);
                newFinding.ConfigureAssessmentDetails(currentAssessment.Id, "xss", "High",
                    "https://10.4.5.6/search", "GET", "q", "New finding", "impact", null, "fix", null,
                    WebCheckStatus.FindingDetected);
                var successfulRecheck = new WebAssessmentCheck(tenant.Id, currentAssessment.Id,
                    "security-headers", "Security headers", "security-headers", WebCheckStatus.Passed,
                    "https://10.4.5.6/headers");
                completeCurrent.AddRange(newFinding, successfulRecheck);
                await completeCurrent.SaveChangesAsync();
            }

            // Competing API-hosted schedulers all observe the same completed queued run.
            // The transaction, schedule row-version and unique event/notification indexes must
            // allow exactly one reconciliation to persist the comparison.
            await Task.WhenAll(processors.Select(processor => processor.RunOnceAsync(batchSize: 20)));

            await using var verify = new AppDbContext(options);
            var completedRun = await verify.AssessmentScheduleRuns.SingleAsync(x => x.ScheduleId == schedule.Id);
            Assert.Equal(AssessmentScheduleRunStatus.Completed, completedRun.Status);
            Assert.NotNull(completedRun.ComparedAt);

            var driftEvents = await verify.AssessmentDriftEvents
                .Where(x => x.TenantId == tenant.Id && x.ScheduleRunId == completedRun.Id)
                .ToListAsync();
            Assert.Equal(2, driftEvents.Count);
            Assert.Contains(driftEvents, x => x.EventType == "NewFinding");
            Assert.Contains(driftEvents, x => x.EventType == "NoLongerObserved");

            var notifications = await verify.Notifications
                .Where(x => x.TenantId == tenant.Id && x.Channel == "in-app")
                .ToListAsync();
            Assert.Equal(2, notifications.Count);
            Assert.Equal(2, notifications.Select(x => x.ResourceId).Distinct().Count());
        }
        finally
        {
            await DropSchemaAsync(connectionString!, schema);
        }
    }

    private static async Task CreateSchemaAsync(string connectionString, string schema)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"CREATE SCHEMA \"{schema}\"";
        await command.ExecuteNonQueryAsync();
    }

    private static async Task DropSchemaAsync(string connectionString, string schema)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"DROP SCHEMA IF EXISTS \"{schema}\" CASCADE";
        await command.ExecuteNonQueryAsync();
    }

    private static string WithSearchPath(string connectionString, string schema)
    {
        var builder = new NpgsqlConnectionStringBuilder(connectionString) { SearchPath = schema };
        return builder.ConnectionString;
    }

    private static async Task<bool> ObjectExistsAsync(string connectionString, string kind, string name)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = kind switch
        {
            "table" => "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = @name)",
            "column" => "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'Notifications' AND column_name = @name)",
            "index" => "SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = @name)",
            "constraint" => "SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = @name)",
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null)
        };
        command.Parameters.AddWithValue("name", name);
        return (bool)(await command.ExecuteScalarAsync() ?? false);
    }

    private static AssessmentScheduleProcessor CreateProcessor(DbContextOptions<AppDbContext> options)
        => new(new ContextFactory(options), new AcceptingScopeValidator(), new EmptyQueue(),
            NullLogger<AssessmentScheduleProcessor>.Instance);

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
