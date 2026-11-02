using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;
using SentinelAI.Security.Policy;

namespace SentinelAI.IntegrationTests;

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
            db.Add(new AssetService(tenant.Id, asset.Id, "https", 443, "web", "1"));
            await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        }
        finally
        {
            await db.AssetServices.Where(x => x.TenantId == tenant.Id || x.TenantId == otherTenant.Id).ExecuteDeleteAsync();
            await db.Assets.Where(x => x.TenantId == tenant.Id || x.TenantId == otherTenant.Id).ExecuteDeleteAsync();
            await db.TargetScopes.Where(x => x.TenantId == tenant.Id || x.TenantId == otherTenant.Id).ExecuteDeleteAsync();
            await db.Tenants.Where(x => x.Id == tenant.Id || x.Id == otherTenant.Id).ExecuteDeleteAsync();
        }
    }

    private sealed class EmptyResolver : IHostAddressResolver
    {
        public Task<IReadOnlyCollection<System.Net.IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyCollection<System.Net.IPAddress>>([]);
    }
}
