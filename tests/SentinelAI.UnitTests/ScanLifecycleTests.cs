using Microsoft.EntityFrameworkCore;
using SentinelAI.Application;
using SentinelAI.Contracts;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;
using SentinelAI.Security.Policy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace SentinelAI.UnitTests;

public sealed class ScanLifecycleTests
{
    [Fact]
    public async Task Authorized_scan_is_persisted_and_queued()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        await using var db = new AppDbContext(options);
        var tenant = new Tenant("Test tenant"); db.Tenants.Add(tenant);
        var user = new User(tenant.Id, "analyst", "Analyst", UserRole.SecurityAnalyst); db.Users.Add(user);
        var scope = new TargetScope(tenant.Id, "private-lab", user.Id, DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], ["mock-passive"], 10, 120, "approval-1", false); db.TargetScopes.Add(scope);
        await db.SaveChangesAsync();
        var queue = new InMemoryScanJobQueue();
        var service = new ScanService(db, new TargetScopeValidator(new StubResolver()), queue);

        var result = await service.CreateAsync(new PrincipalContext(tenant.Id, user.Id, user.Subject, user.Role), new CreateScanRequest(scope.Id, "mock-passive"), CancellationToken.None);

        Assert.Equal(ScanJobStatus.Queued, result.Status);
        Assert.Single(await db.AgentJobs.ToListAsync());
        Assert.Single(await db.OutboxMessages.ToListAsync());
        Assert.Equal(result.Id, (await queue.ReadAllAsync().FirstAsync()).JobId);
    }

    [Fact]
    public async Task Cancellation_during_execution_never_completes_the_job()
    {
        var databaseName = Guid.NewGuid().ToString();
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(databaseName).Options;
        await using var db = new AppDbContext(options);
        var tenant = new Tenant("Cancellation tenant"); var user = new User(tenant.Id, "analyst", "Analyst", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "private-lab", user.Id, DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], ["mock-passive"], 10, 120, "approval-1", false);
        db.Tenants.Add(tenant); db.Users.Add(user); db.TargetScopes.Add(scope);
        var job = new AgentJob(tenant.Id, scope.Id, user.Id, "mock-passive");
        db.AgentJobs.Add(job); db.AgentExecutions.Add(new AgentExecution(job.Id, "MockNetworkDiscoveryAgent"));
        await db.SaveChangesAsync();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Worker:ExecutionDelayMs"] = "500" }).Build();
        var service = new ScanExecutionService(db, new TargetScopeValidator(new StubResolver()), configuration, NullLogger<ScanExecutionService>.Instance);
        using var cancellation = new CancellationTokenSource();
        var running = service.ExecuteAsync(job.Id, cancellation.Token);
        await Task.Delay(100);
        await using (var cancelDb = new AppDbContext(options))
        {
            var persisted = await cancelDb.AgentJobs.SingleAsync(x => x.Id == job.Id);
            persisted.Cancel(); await cancelDb.SaveChangesAsync();
        }
        cancellation.Cancel();
        await running;
        await db.Entry(job).ReloadAsync();
        Assert.Equal(ScanJobStatus.Cancelled, job.Status);
        Assert.NotEqual(ScanJobStatus.Completed, job.Status);
    }

    [Fact]
    public void Cancellation_before_execution_prevents_a_worker_claim()
    {
        var job = new AgentJob(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "mock-passive");
        job.Cancel();
        Assert.False(job.TryClaim("worker-a"));
        Assert.Equal(ScanJobStatus.Cancelled, job.Status);
    }

    [Fact]
    public void A_worker_cannot_claim_a_job_already_bound_to_another_worker()
    {
        var job = new AgentJob(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "mock-passive");
        Assert.True(job.TryClaim("worker-a"));
        Assert.False(job.TryClaim("worker-b"));
    }

    [Fact]
    public async Task Running_jobs_are_requeued_after_worker_restart()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        await using var db = new AppDbContext(options);
        var tenant = new Tenant("Recovery tenant"); var user = new User(tenant.Id, "analyst", "Analyst", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "private-lab", user.Id, DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], ["mock-passive"], 10, 120, "approval-1", false);
        var job = new AgentJob(tenant.Id, scope.Id, user.Id, "mock-passive");
        var execution = new AgentExecution(job.Id, "MockNetworkDiscoveryAgent");
        db.Tenants.Add(tenant); db.Users.Add(user); db.TargetScopes.Add(scope); db.AgentJobs.Add(job); db.AgentExecutions.Add(execution);
        job.Start(); execution.Start(); await db.SaveChangesAsync();
        var service = new ScanExecutionService(db, new TargetScopeValidator(new StubResolver()), new ConfigurationBuilder().Build(), NullLogger<ScanExecutionService>.Instance);
        await service.RecoverInterruptedJobsAsync(CancellationToken.None, tenant.Id);
        await db.Entry(job).ReloadAsync();
        Assert.Equal(ScanJobStatus.Queued, job.Status);
        Assert.Equal(AgentExecutionStatus.Pending, (await db.AgentExecutions.SingleAsync()).Status);
    }

    private sealed class StubResolver : IHostAddressResolver
    {
        public Task<IReadOnlyCollection<System.Net.IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyCollection<System.Net.IPAddress>>([]);
    }
}
