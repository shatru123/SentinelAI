using System.Data;
using System.Net;
using System.Runtime.CompilerServices;
using Microsoft.EntityFrameworkCore;
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
            var schedule = new AssessmentSchedule(tenant.Id, scope.Id, creatorId,
                WebAssessmentOperationProfiles.Passive, scope.GetAuthorizationFingerprint(),
                24, now.AddDays(5), now.AddHours(-25));

            await using (var seed = new AppDbContext(options))
            {
                // The schedule's custom composite scope FK is introduced by raw migration SQL and
                // has no EF navigation relationship; persist its principals before the dependent.
                seed.AddRange(tenant, creator, scope, worker);
                await seed.SaveChangesAsync();
                seed.AssessmentSchedules.Add(schedule);
                await seed.SaveChangesAsync();
            }

            var processors = Enumerable.Range(0, 8).Select(_ => CreateProcessor(options)).ToArray();
            await Task.WhenAll(processors.Select(processor => processor.RunOnceAsync(batchSize: 20)));
            // Subsequent cycles simulate recovery/retry after multiple scheduler instances observed the same work.
            await Task.WhenAll(processors.Select(processor => processor.RunOnceAsync(batchSize: 20)));

            await using var verify = new AppDbContext(options);
            var runs = await verify.AssessmentScheduleRuns.Where(x => x.TenantId == tenant.Id && x.ScheduleId == schedule.Id).ToListAsync();
            Assert.Single(runs);
            Assert.Equal(AssessmentScheduleRunStatus.Queued, runs[0].Status);
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
