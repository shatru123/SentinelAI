using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SentinelAI.Application;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;
using SentinelAI.Security.Policy;

namespace SentinelAI.IntegrationTests;

[Collection("PostgreSQL integration")]
public sealed class PostgresReliabilityTests
{
    [Fact]
    public async Task Postgres_persists_worker_capacity_and_concurrent_lease_ownership()
    {
        var connection = Environment.GetEnvironmentVariable("SENTINELAI_POSTGRES_CONNECTION")
            ?? "Host=localhost;Port=5432;Database=sentinelai;Username=sentinelai;Password=replace-with-local-dev-password";
        var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(connection).Options;
        await using var db = new AppDbContext(options);
        await db.Database.MigrateAsync();

        var tenant = new Tenant($"integration-{Guid.NewGuid():N}");
        var worker = new WorkerRegistration(tenant.Id, $"worker-{Guid.NewGuid():N}", "test", ["passive-mock"]);
        worker.Heartbeat(1, 4, DateTimeOffset.UtcNow.AddSeconds(-1), DateTimeOffset.UtcNow);
        var user = new User(tenant.Id, $"subject-{Guid.NewGuid():N}", "Integration", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "private", user.Id, DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], ["mock-passive"], 10, 120, "integration", false);
        var job = new AgentJob(tenant.Id, scope.Id, user.Id, "mock-passive");
        var message = new OutboxMessage(tenant.Id, "test", "{}");
        db.AddRange(tenant, worker, user, scope, job, new AgentExecution(job.Id, "test"), message);
        await db.SaveChangesAsync();

        try
        {
            await using var competingDb = new AppDbContext(options);
            var firstView = await db.AgentJobs.SingleAsync(x => x.Id == job.Id);
            var secondView = await competingDb.AgentJobs.SingleAsync(x => x.Id == job.Id);
            Assert.True(firstView.TryAcquireLease(worker.Identity, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1)));
            await db.SaveChangesAsync();
            Assert.True(secondView.TryAcquireLease("another-worker", DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1)));
            await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => competingDb.SaveChangesAsync());

            var persistedWorker = await db.Workers.AsNoTracking().SingleAsync(x => x.Id == worker.Id);
            var persistedJob = await db.AgentJobs.AsNoTracking().SingleAsync(x => x.Id == job.Id);
            Assert.Equal(1, persistedWorker.CurrentActiveJobs);
            Assert.Equal(4, persistedWorker.MaximumCapacity);
            Assert.Equal(worker.Identity, persistedJob.LeaseOwnerWorkerId);
            Assert.NotNull(persistedJob.LeaseExpiresAt);
        }
        finally
        {
            await db.OutboxMessages.Where(x => x.Id == message.Id).ExecuteDeleteAsync();
            await db.AgentExecutions.Where(x => x.AgentJobId == job.Id).ExecuteDeleteAsync();
            await db.AgentJobs.Where(x => x.Id == job.Id).ExecuteDeleteAsync();
            await db.TargetScopes.Where(x => x.Id == scope.Id).ExecuteDeleteAsync();
            await db.Workers.Where(x => x.Id == worker.Id).ExecuteDeleteAsync();
            await db.Users.Where(x => x.Id == user.Id).ExecuteDeleteAsync();
            await db.Tenants.Where(x => x.Id == tenant.Id).ExecuteDeleteAsync();
        }
    }

    [Fact]
    public async Task Postgres_recovers_legacy_unleased_running_jobs_concurrently()
    {
        var connection = Environment.GetEnvironmentVariable("SENTINELAI_POSTGRES_CONNECTION")
            ?? "Host=localhost;Port=5432;Database=sentinelai;Username=sentinelai;Password=replace-with-local-dev-password";
        var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(connection).Options;
        await using var db = new AppDbContext(options);
        await db.Database.MigrateAsync();

        var tenant = new Tenant($"legacy-{Guid.NewGuid():N}");
        var user = new User(tenant.Id, $"subject-{Guid.NewGuid():N}", "Integration", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "private", user.Id, DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], ["mock-passive"], 10, 120, "integration", false);
        var job = new AgentJob(tenant.Id, scope.Id, user.Id, "mock-passive");
        var execution = new AgentExecution(job.Id, "test");
        Assert.True(job.TryAcquireLease("legacy-worker", DateTimeOffset.UtcNow.AddMinutes(-2), TimeSpan.FromSeconds(1)));
        execution.Start();
        db.AddRange(tenant, user, scope, job, execution);
        await db.SaveChangesAsync();

        try
        {
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"AgentJobs\" SET \"Status\" = {(int)ScanJobStatus.Running}, \"LeaseExpiresAt\" = NULL WHERE \"Id\" = {job.Id}");
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"AgentExecutions\" SET \"Status\" = {(int)AgentExecutionStatus.Running} WHERE \"AgentJobId\" = {job.Id}");

            await using var firstDb = new AppDbContext(options);
            await using var secondDb = new AppDbContext(options);
            var first = new ScanExecutionService(firstDb, new TargetScopeValidator(new EmptyResolver()), new ConfigurationBuilder().Build(), NullLogger<ScanExecutionService>.Instance);
            var second = new ScanExecutionService(secondDb, new TargetScopeValidator(new EmptyResolver()), new ConfigurationBuilder().Build(), NullLogger<ScanExecutionService>.Instance);

            await Task.WhenAll(
                first.RecoverExpiredLeasesAsync(CancellationToken.None, tenant.Id),
                second.RecoverExpiredLeasesAsync(CancellationToken.None, tenant.Id));

            var recovered = await db.AgentJobs.AsNoTracking().SingleAsync(x => x.Id == job.Id);
            var recoveredExecution = await db.AgentExecutions.AsNoTracking().SingleAsync(x => x.AgentJobId == job.Id);
            Assert.Equal(ScanJobStatus.Queued, recovered.Status);
            Assert.Equal(AgentExecutionStatus.Pending, recoveredExecution.Status);
            Assert.Null(recovered.LeaseOwnerWorkerId);
            Assert.Null(recovered.LeaseExpiresAt);
        }
        finally
        {
            await db.AgentExecutions.Where(x => x.AgentJobId == job.Id).ExecuteDeleteAsync();
            await db.AgentJobs.Where(x => x.Id == job.Id).ExecuteDeleteAsync();
            await db.TargetScopes.Where(x => x.Id == scope.Id).ExecuteDeleteAsync();
            await db.Users.Where(x => x.Id == user.Id).ExecuteDeleteAsync();
            await db.Tenants.Where(x => x.Id == tenant.Id).ExecuteDeleteAsync();
        }
    }

    [Fact]
    public async Task Postgres_enforces_tenant_scoped_asset_and_service_uniqueness()
    {
        var connection = Environment.GetEnvironmentVariable("SENTINELAI_POSTGRES_CONNECTION")
            ?? "Host=localhost;Port=5432;Database=sentinelai;Username=sentinelai;Password=replace-with-local-dev-password";
        var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(connection).Options;
        await using var db = new AppDbContext(options);
        await db.Database.MigrateAsync();

        var tenant = new Tenant($"inventory-unique-{Guid.NewGuid():N}");
        var otherTenant = new Tenant($"inventory-other-{Guid.NewGuid():N}");
        var scope = new TargetScope(tenant.Id, "private", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        var otherScope = new TargetScope(otherTenant.Id, "private", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        var asset = new Asset(tenant.Id, scope.Id, "10.60.0.5", TargetKind.Network);
        db.AddRange(tenant, otherTenant, scope, otherScope, asset);
        await db.SaveChangesAsync();

        try
        {
            var sameTenantDuplicate = new Asset(tenant.Id, scope.Id, asset.Address, TargetKind.Network);
            db.Add(sameTenantDuplicate);
            await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
            db.ChangeTracker.Clear();

            var otherTenantAsset = new Asset(otherTenant.Id, otherScope.Id, asset.Address, TargetKind.Network);
            db.Add(otherTenantAsset);
            await db.SaveChangesAsync();

            db.Add(new AssetService(tenant.Id, asset.Id, "https", 443, "web", "1"));
            await db.SaveChangesAsync();

            db.Add(new AssetService(otherTenant.Id, asset.Id, "https", 443, "cross-tenant", "1"));
            await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
            db.ChangeTracker.Clear();

            db.Add(new AssetService(tenant.Id, Guid.NewGuid(), "https", 8443, "orphan", "1"));
            await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
            db.ChangeTracker.Clear();

            db.Add(new AssetService(tenant.Id, asset.Id, "https", 443, "web", "1"));
            await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());

            db.ChangeTracker.Clear();
            await db.Assets.Where(x => x.Id == asset.Id).ExecuteDeleteAsync();
            Assert.Empty(await db.AssetServices.Where(x => x.AssetId == asset.Id).ToListAsync());
        }
        finally
        {
            await db.AssetServices.Where(x => x.TenantId == tenant.Id || x.TenantId == otherTenant.Id).ExecuteDeleteAsync();
            await db.Assets.Where(x => x.TenantId == tenant.Id || x.TenantId == otherTenant.Id).ExecuteDeleteAsync();
            await db.TargetScopes.Where(x => x.TenantId == tenant.Id || x.TenantId == otherTenant.Id).ExecuteDeleteAsync();
            await db.Tenants.Where(x => x.Id == tenant.Id || x.Id == otherTenant.Id).ExecuteDeleteAsync();
        }
    }

    [Fact]
    public async Task Postgres_backfills_reachability_history_without_overwriting_observation_or_existing_values()
    {
        var connection = PostgreSqlConnection();
        var schema = $"migration_{Guid.NewGuid():N}";
        await CreateSchemaAsync(connection, schema);
        try
        {
            var isolatedConnection = new NpgsqlConnectionStringBuilder(connection) { SearchPath = schema }.ConnectionString;
            var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(isolatedConnection).Options;
            var tenantId = Guid.NewGuid();
            var scopeId = Guid.NewGuid();
            var onlineId = Guid.NewGuid();
            var offlineId = Guid.NewGuid();
            var existingOnlineId = Guid.NewGuid();
            var observedAt = NormalizePostgreSqlTimestamp(DateTimeOffset.UtcNow.AddHours(-2));
            var existingObservedAt = NormalizePostgreSqlTimestamp(DateTimeOffset.UtcNow.AddHours(-3));
            var existingReachability = NormalizePostgreSqlTimestamp(DateTimeOffset.UtcNow.AddHours(-4));

            await using (var db = new AppDbContext(options))
            {
                await db.Database.MigrateAsync("20261102160000_Phase21AssetObservationSemantics");
                await db.Database.ExecuteSqlInterpolatedAsync($"""
                    INSERT INTO "Assets" ("Id", "TenantId", "ScopeId", "Address", "Kind", "IsOnline", "LastObservedAt", "LastSuccessfulReachabilityAt")
                    VALUES ({onlineId}, {tenantId}, {scopeId}, {"10.61.0.5"}, {(int)TargetKind.Network}, {true}, {observedAt}, {null});
                    INSERT INTO "Assets" ("Id", "TenantId", "ScopeId", "Address", "Kind", "IsOnline", "LastObservedAt", "LastSuccessfulReachabilityAt")
                    VALUES ({offlineId}, {tenantId}, {scopeId}, {"10.61.0.6"}, {(int)TargetKind.Network}, {false}, {observedAt}, {null});
                    INSERT INTO "Assets" ("Id", "TenantId", "ScopeId", "Address", "Kind", "IsOnline", "LastObservedAt", "LastSuccessfulReachabilityAt")
                    VALUES ({existingOnlineId}, {tenantId}, {scopeId}, {"10.61.0.7"}, {(int)TargetKind.Network}, {(true)}, {existingObservedAt}, {existingReachability});
                    """);

                await db.Database.MigrateAsync();
                Assert.Contains("20261102170000_Phase211ReachabilityHistoryBackfill", await db.Database.GetAppliedMigrationsAsync());

                var persistedOnline = await db.Assets.AsNoTracking().SingleAsync(x => x.Id == onlineId);
                var persistedOffline = await db.Assets.AsNoTracking().SingleAsync(x => x.Id == offlineId);
                var persistedExisting = await db.Assets.AsNoTracking().SingleAsync(x => x.Id == existingOnlineId);
                Assert.Equal(tenantId, persistedOnline.TenantId);
                Assert.Equal(observedAt, persistedOnline.LastObservedAt);
                Assert.Equal(observedAt, persistedOnline.LastSuccessfulReachabilityAt);
                Assert.Equal(offlineId, persistedOffline.Id);
                Assert.Equal(observedAt, persistedOffline.LastObservedAt);
                Assert.Null(persistedOffline.LastSuccessfulReachabilityAt);
                Assert.Equal(existingObservedAt, persistedExisting.LastObservedAt);
                Assert.Equal(existingReachability, persistedExisting.LastSuccessfulReachabilityAt);
            }
        }
        finally
        {
            await DropSchemaAsync(connection, schema);
        }
    }

    [Fact]
    public async Task Postgres_cancellation_during_collection_persists_no_inventory()
    {
        var connection = Environment.GetEnvironmentVariable("SENTINELAI_POSTGRES_CONNECTION")
            ?? "Host=localhost;Port=5432;Database=sentinelai;Username=sentinelai;Password=replace-with-local-dev-password";
        var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(connection).Options;
        await using var db = new AppDbContext(options);
        await db.Database.MigrateAsync();
        var seed = await SeedInventoryExecutionAsync(db, $"cancel-{Guid.NewGuid():N}");
        var adapter = new PausingInventoryAdapter();
        var service = new ScanExecutionService(db, new TargetScopeValidator(new EmptyResolver()), new ConfigurationBuilder().Build(), NullLogger<ScanExecutionService>.Instance, adapter);
        using var cancellation = new CancellationTokenSource();

        try
        {
            var running = service.ExecuteAsync(seed.JobId, cancellation.Token, seed.TenantId, seed.WorkerIdentity);
            await adapter.Started.Task;
            cancellation.Cancel();
            var outcome = await running;

            Assert.True(adapter.CancellationObserved.Task.IsCompletedSuccessfully);
            Assert.NotEqual(ScanExecutionOutcome.Completed, outcome);
            await using var verifyDb = new AppDbContext(options);
            Assert.Empty(await verifyDb.Assets.Where(x => x.TenantId == seed.TenantId).ToListAsync());
            Assert.Empty(await verifyDb.AssetServices.Where(x => x.TenantId == seed.TenantId).ToListAsync());
            var persistedJob = await verifyDb.AgentJobs.SingleAsync(x => x.Id == seed.JobId);
            Assert.NotEqual(ScanJobStatus.Completed, persistedJob.Status);
            Assert.Equal(AgentExecutionStatus.Pending, (await verifyDb.AgentExecutions.SingleAsync(x => x.AgentJobId == seed.JobId)).Status);
            Assert.Empty(await verifyDb.AuditEvents.Where(x => x.ResourceId == seed.JobId && x.Action == "scan.completed").ToListAsync());
        }
        finally
        {
            await CleanupInventoryExecutionAsync(db, seed.TenantId, seed.JobId, seed.ScopeId, seed.WorkerIdentity);
        }
    }

    [Fact]
    public async Task Postgres_lease_loss_during_collection_persists_no_inventory()
    {
        var connection = Environment.GetEnvironmentVariable("SENTINELAI_POSTGRES_CONNECTION")
            ?? "Host=localhost;Port=5432;Database=sentinelai;Username=sentinelai;Password=replace-with-local-dev-password";
        var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(connection).Options;
        await using var db = new AppDbContext(options);
        await db.Database.MigrateAsync();
        var seed = await SeedInventoryExecutionAsync(db, $"lease-{Guid.NewGuid():N}");
        var adapter = new PausingInventoryAdapter();
        var service = new ScanExecutionService(db, new TargetScopeValidator(new EmptyResolver()), new ConfigurationBuilder().Build(), NullLogger<ScanExecutionService>.Instance, adapter);

        try
        {
            var running = service.ExecuteAsync(seed.JobId, CancellationToken.None, seed.TenantId, seed.WorkerIdentity);
            await adapter.Started.Task;
            await using (var takeoverDb = new AppDbContext(options))
            {
                var takeover = await takeoverDb.AgentJobs.SingleAsync(x => x.Id == seed.JobId);
                takeover.ReleaseLeaseForRetry("integration lease transfer");
                Assert.True(takeover.TryAcquireLease("replacement-worker", DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1)));
                await takeoverDb.SaveChangesAsync();
            }

            adapter.Release();
            var outcome = await running;

            Assert.Equal(ScanExecutionOutcome.ClaimedByAnotherWorker, outcome);
            await using var verifyDb = new AppDbContext(options);
            Assert.Empty(await verifyDb.Assets.Where(x => x.TenantId == seed.TenantId).ToListAsync());
            Assert.Empty(await verifyDb.AssetServices.Where(x => x.TenantId == seed.TenantId).ToListAsync());
            var persistedJob = await verifyDb.AgentJobs.SingleAsync(x => x.Id == seed.JobId);
            Assert.NotEqual(ScanJobStatus.Completed, persistedJob.Status);
            Assert.Equal("replacement-worker", persistedJob.LeaseOwnerWorkerId);
            Assert.NotEqual(AgentExecutionStatus.Completed, (await verifyDb.AgentExecutions.SingleAsync(x => x.AgentJobId == seed.JobId)).Status);
            Assert.Empty(await verifyDb.AuditEvents.Where(x => x.ResourceId == seed.JobId && x.Action == "scan.completed").ToListAsync());
        }
        finally
        {
            await CleanupInventoryExecutionAsync(db, seed.TenantId, seed.JobId, seed.ScopeId, seed.WorkerIdentity);
        }
    }

    private static async Task<InventoryExecutionSeed> SeedInventoryExecutionAsync(AppDbContext db, string workerIdentity)
    {
        var tenant = new Tenant($"execution-{Guid.NewGuid():N}");
        var user = new User(tenant.Id, $"execution-{Guid.NewGuid():N}", "Execution", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "private-execution", user.Id, DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], [InventoryOperationProfiles.NetworkInventoryPassive], 10, 120, "phase21.1-execution", false);
        var worker = new WorkerRegistration(tenant.Id, workerIdentity, "test", ["passive-inventory"]);
        worker.Heartbeat(0, 1);
        var job = new AgentJob(tenant.Id, scope.Id, user.Id, InventoryOperationProfiles.NetworkInventoryPassive);
        db.AddRange(tenant, user, scope, worker, job, new AgentExecution(job.Id, "PausingInventoryAdapter"));
        await db.SaveChangesAsync();
        return new InventoryExecutionSeed(tenant.Id, scope.Id, job.Id, workerIdentity);
    }

    private static async Task CleanupInventoryExecutionAsync(AppDbContext db, Guid tenantId, Guid jobId, Guid scopeId, string workerIdentity)
    {
        await db.AssetServices.Where(x => x.TenantId == tenantId).ExecuteDeleteAsync();
        await db.Assets.Where(x => x.TenantId == tenantId).ExecuteDeleteAsync();
        await db.AgentExecutions.Where(x => x.AgentJobId == jobId).ExecuteDeleteAsync();
        await db.AgentJobs.Where(x => x.Id == jobId).ExecuteDeleteAsync();
        await db.TargetScopes.Where(x => x.Id == scopeId).ExecuteDeleteAsync();
        await db.Workers.Where(x => x.TenantId == tenantId && x.Identity == workerIdentity).ExecuteDeleteAsync();
        await db.Users.Where(x => x.TenantId == tenantId).ExecuteDeleteAsync();
        await db.Tenants.Where(x => x.Id == tenantId).ExecuteDeleteAsync();
    }

    private static string PostgreSqlConnection()
        => Environment.GetEnvironmentVariable("SENTINELAI_POSTGRES_CONNECTION")
            ?? "Host=localhost;Port=5432;Database=sentinelai;Username=sentinelai;Password=replace-with-local-dev-password";

    private static DateTimeOffset NormalizePostgreSqlTimestamp(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        return new DateTimeOffset(utc.Ticks - utc.Ticks % 10, TimeSpan.Zero);
    }

    private static async Task CreateSchemaAsync(string connection, string schema)
    {
        await using var database = new NpgsqlConnection(connection);
        await database.OpenAsync();
        await using var command = new NpgsqlCommand($"CREATE SCHEMA \"{schema}\"", database);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task DropSchemaAsync(string connection, string schema)
    {
        await using var database = new NpgsqlConnection(connection);
        await database.OpenAsync();
        await using var command = new NpgsqlCommand($"DROP SCHEMA IF EXISTS \"{schema}\" CASCADE", database);
        await command.ExecuteNonQueryAsync();
    }

    private sealed record InventoryExecutionSeed(Guid TenantId, Guid ScopeId, Guid JobId, string WorkerIdentity);

    private sealed class PausingInventoryAdapter : IPassiveInventoryAdapter
    {
        private readonly TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource CancellationObserved { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<IReadOnlyCollection<InventoryObservation>> CollectAsync(IReadOnlyCollection<AuthorizedInventoryTarget> targets, int requestsPerMinute, CancellationToken cancellationToken = default)
        {
            Started.TrySetResult();
            try { await release.Task.WaitAsync(cancellationToken); }
            catch (OperationCanceledException) { CancellationObserved.TrySetResult(); throw; }
            return [new InventoryObservation("10.70.0.5", TargetKind.Network, false, [])];
        }

        public void Release() => release.TrySetResult();
    }

    private sealed class EmptyResolver : IHostAddressResolver
    {
        public Task<IReadOnlyCollection<System.Net.IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyCollection<System.Net.IPAddress>>([]);
    }
}
