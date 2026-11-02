using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;

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
}
