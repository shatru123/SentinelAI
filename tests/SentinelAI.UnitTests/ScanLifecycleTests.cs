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
    public void Passive_observation_never_claims_reachability_and_preserves_last_successful_timestamp()
    {
        var asset = new Asset(Guid.NewGuid(), Guid.NewGuid(), "10.20.0.5", TargetKind.Network);
        asset.RecordReachabilityConfirmation();
        var lastReachable = asset.LastSuccessfulReachabilityAt;

        asset.RecordPassiveObservation();

        Assert.False(asset.IsOnline);
        Assert.NotEqual(default, asset.LastObservedAt);
        Assert.Equal(lastReachable, asset.LastSuccessfulReachabilityAt);
    }

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
    public async Task Worker_without_passive_inventory_capability_cannot_execute_the_profile()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        await using var db = new AppDbContext(options);
        var tenant = new Tenant("Capability tenant");
        var user = new User(tenant.Id, "analyst", "Analyst", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "private", user.Id, DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], [InventoryOperationProfiles.NetworkInventoryPassive], 10, 120, "ticket", false);
        var worker = new WorkerRegistration(tenant.Id, "mock-only", "test", ["passive-mock"]);
        worker.Heartbeat(0, 1);
        var job = new AgentJob(tenant.Id, scope.Id, user.Id, InventoryOperationProfiles.NetworkInventoryPassive);
        db.AddRange(tenant, user, scope, worker, job, new AgentExecution(job.Id, "PassiveNetworkInventoryAdapter"));
        await db.SaveChangesAsync();
        var service = new ScanExecutionService(db, new TargetScopeValidator(new EmptyResolver()), new ConfigurationBuilder().Build(), NullLogger<ScanExecutionService>.Instance);

        var outcome = await service.ExecuteAsync(job.Id, CancellationToken.None, tenant.Id, worker.Identity);

        Assert.Equal(ScanExecutionOutcome.Unauthorized, outcome);
        Assert.Empty(await db.Assets.ToListAsync());
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
    public async Task Cancellation_during_inventory_collection_observes_cancellation_and_persists_no_inventory()
    {
        var databaseName = Guid.NewGuid().ToString();
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(databaseName).Options;
        var (tenantId, jobId, workerId) = await SeedInventoryJobAsync(options, "cancellation-worker");
        var adapter = new ControlledInventoryAdapter([new InventoryObservation("10.30.0.5", TargetKind.Network, false, [])]);
        await using var db = new AppDbContext(options);
        var service = new ScanExecutionService(db, new TargetScopeValidator(new StubResolver()), new ConfigurationBuilder().Build(), NullLogger<ScanExecutionService>.Instance, adapter);
        using var cancellation = new CancellationTokenSource();

        var running = service.ExecuteAsync(jobId, cancellation.Token, tenantId, workerId);
        await adapter.Started.Task;
        cancellation.Cancel();
        var outcome = await running;

        Assert.True(adapter.CancellationObserved.Task.IsCompletedSuccessfully);
        Assert.NotEqual(ScanExecutionOutcome.Completed, outcome);
        await using var verifyDb = new AppDbContext(options);
        Assert.Empty(await verifyDb.Assets.ToListAsync());
        Assert.NotEqual(ScanJobStatus.Completed, (await verifyDb.AgentJobs.SingleAsync(x => x.Id == jobId)).Status);
    }

    [Fact]
    public async Task Lease_loss_during_inventory_collection_prevents_final_inventory_commit()
    {
        var databaseName = Guid.NewGuid().ToString();
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(databaseName).Options;
        var (tenantId, jobId, workerId) = await SeedInventoryJobAsync(options, "lease-worker");
        var adapter = new ControlledInventoryAdapter([new InventoryObservation("10.31.0.5", TargetKind.Network, false, [])]);
        await using var db = new AppDbContext(options);
        var service = new ScanExecutionService(db, new TargetScopeValidator(new StubResolver()), new ConfigurationBuilder().Build(), NullLogger<ScanExecutionService>.Instance, adapter);
        var running = service.ExecuteAsync(jobId, CancellationToken.None, tenantId, workerId);
        await adapter.Started.Task;

        await using (var takeoverDb = new AppDbContext(options))
        {
            var takeover = await takeoverDb.AgentJobs.SingleAsync(x => x.Id == jobId);
            takeover.ReleaseLeaseForRetry("test lease transfer");
            Assert.True(takeover.TryAcquireLease("replacement-worker", DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1)));
            await takeoverDb.SaveChangesAsync();
        }

        adapter.Release();
        var outcome = await running;

        Assert.Equal(ScanExecutionOutcome.ClaimedByAnotherWorker, outcome);
        await using var verifyDb = new AppDbContext(options);
        Assert.Empty(await verifyDb.Assets.ToListAsync());
        Assert.NotEqual(ScanJobStatus.Completed, (await verifyDb.AgentJobs.SingleAsync(x => x.Id == jobId)).Status);
    }

    [Fact]
    public async Task Cancellation_between_inventory_observations_leaves_no_partial_records()
    {
        var databaseName = Guid.NewGuid().ToString();
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(databaseName).Options;
        var (tenantId, jobId, workerId) = await SeedInventoryJobAsync(options, "multi-observation-worker");
        using var cancellation = new CancellationTokenSource();
        var adapter = new CancellationAfterFirstObservationAdapter(cancellation, [
            new InventoryObservation("10.32.0.5", TargetKind.Network, false, []),
            new InventoryObservation("10.32.0.6", TargetKind.Network, false, [])]);
        await using var db = new AppDbContext(options);
        var service = new ScanExecutionService(db, new TargetScopeValidator(new StubResolver()), new ConfigurationBuilder().Build(), NullLogger<ScanExecutionService>.Instance, adapter);

        var outcome = await service.ExecuteAsync(jobId, cancellation.Token, tenantId, workerId);

        Assert.NotEqual(ScanExecutionOutcome.Completed, outcome);
        await using var verifyDb = new AppDbContext(options);
        Assert.Empty(await verifyDb.Assets.ToListAsync());
    }

    [Fact]
    public async Task Excluded_inventory_target_is_rejected_before_persistence()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        await using var db = new AppDbContext(options);
        var tenant = new Tenant("excluded-inventory");
        var user = new User(tenant.Id, "excluded-operator", "Excluded", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "excluded-scope", user.Id, DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.50.0.1")], ["10.50.0.0/30"], [InventoryOperationProfiles.NetworkInventoryPassive], 10, 120, "phase21.1-exclusion", false);
        var worker = new WorkerRegistration(tenant.Id, "excluded-worker", "test", ["passive-inventory"]);
        worker.Heartbeat(0, 1);
        var job = new AgentJob(tenant.Id, scope.Id, user.Id, InventoryOperationProfiles.NetworkInventoryPassive);
        db.AddRange(tenant, user, scope, worker, job, new AgentExecution(job.Id, "PassiveNetworkInventoryAdapter"));
        await db.SaveChangesAsync();
        var service = new ScanExecutionService(db, new TargetScopeValidator(new StubResolver()), new ConfigurationBuilder().Build(), NullLogger<ScanExecutionService>.Instance);

        await Assert.ThrowsAsync<ScopeValidationException>(() => service.ExecuteAsync(job.Id, CancellationToken.None, tenant.Id, worker.Identity));

        Assert.Empty(await db.Assets.ToListAsync());
        Assert.NotEqual(ScanJobStatus.Completed, (await db.AgentJobs.SingleAsync(x => x.Id == job.Id)).Status);
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
    public void Full_heartbeat_capacity_does_not_block_admission_when_local_worker_has_a_slot()
    {
        var worker = new WorkerRegistration(Guid.NewGuid(), "worker-a", "test", ["passive-mock"]);
        worker.Heartbeat(activeJobs: 4, capacity: 4);

        Assert.True(worker.IsAvailable(DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void Lease_renewal_rejects_expired_or_changed_ownership()
    {
        var job = new AgentJob(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "mock-passive");
        var acquiredAt = DateTimeOffset.UtcNow;
        Assert.True(job.TryAcquireLease("worker-a", acquiredAt, TimeSpan.FromSeconds(5)));
        Assert.False(job.RenewLease("worker-b", acquiredAt.AddSeconds(1), TimeSpan.FromSeconds(5)));
        Assert.False(job.RenewLease("worker-a", acquiredAt.AddSeconds(6), TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public void Failure_recovery_cannot_release_a_lease_owned_by_another_worker()
    {
        var job = new AgentJob(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "mock-passive");
        Assert.True(job.TryAcquireLease("worker-a", DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1)));
        var before = job.LeaseOwnerWorkerId;

        Assert.True(job.IsLeaseOwnedBy("worker-a", DateTimeOffset.UtcNow));
        Assert.False(job.IsLeaseOwnedBy("worker-b", DateTimeOffset.UtcNow));
        Assert.Equal(before, job.LeaseOwnerWorkerId);
    }

    [Fact]
    public async Task Failure_requeue_requires_the_current_lease_owner()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        await using var db = new AppDbContext(options);
        var tenant = new Tenant("requeue tenant");
        var user = new User(tenant.Id, "analyst", "Analyst", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "private", user.Id, DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], ["mock-passive"], 10, 120, "ticket", false);
        var job = new AgentJob(tenant.Id, scope.Id, user.Id, "mock-passive");
        var execution = new AgentExecution(job.Id, "test");
        db.AddRange(tenant, user, scope, job, execution);
        Assert.True(job.TryAcquireLease("worker-a", DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1)));
        execution.Start();
        await db.SaveChangesAsync();
        var service = new ScanExecutionService(db, new TargetScopeValidator(new EmptyResolver()), new ConfigurationBuilder().Build(), NullLogger<ScanExecutionService>.Instance);

        var changed = await service.RequeueOrFailAsync(job.Id, "worker-b", 1, 3, "stale worker", CancellationToken.None);

        Assert.False(changed);
        Assert.Equal(ScanJobStatus.Running, job.Status);
        Assert.Equal("worker-a", job.LeaseOwnerWorkerId);
    }

    [Fact]
    public async Task Execution_stops_without_asset_side_effect_after_lease_ownership_changes()
    {
        var databaseName = Guid.NewGuid().ToString();
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(databaseName).Options;
        await using var db = new AppDbContext(options);
        var tenant = new Tenant("ownership tenant");
        var user = new User(tenant.Id, "analyst", "Analyst", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "private", user.Id, DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], ["mock-passive"], 10, 120, "ticket", false);
        var worker = new WorkerRegistration(tenant.Id, "worker-a", "test", ["passive-mock"]);
        worker.Heartbeat(0, 2);
        var job = new AgentJob(tenant.Id, scope.Id, user.Id, "mock-passive");
        var execution = new AgentExecution(job.Id, "test");
        db.AddRange(tenant, user, scope, worker, job, execution);
        await db.SaveChangesAsync();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Worker:ExecutionDelayMs"] = "500" }).Build();
        var service = new ScanExecutionService(db, new TargetScopeValidator(new EmptyResolver()), configuration, NullLogger<ScanExecutionService>.Instance);
        var running = service.ExecuteAsync(job.Id, CancellationToken.None, tenant.Id, worker.Identity);

        await using var competingDb = new AppDbContext(options);
        AgentJob? competingJob = null;
        for (var attempt = 0; attempt < 100 && competingJob is null; attempt++)
        {
            competingJob = await competingDb.AgentJobs.AsNoTracking().SingleAsync(x => x.Id == job.Id);
            if (competingJob.LeaseOwnerWorkerId is null) { competingJob = null; await Task.Delay(10); }
        }
        Assert.NotNull(competingJob);
        var takeover = await competingDb.AgentJobs.SingleAsync(x => x.Id == job.Id);
        takeover.ReleaseLeaseForRetry("lease handoff");
        Assert.True(takeover.TryAcquireLease("worker-b", DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1)));
        await competingDb.SaveChangesAsync();

        var outcome = await running;

        Assert.Equal(ScanExecutionOutcome.ClaimedByAnotherWorker, outcome);
        Assert.Empty(await db.Assets.ToListAsync());
    }

    [Fact]
    public async Task A_healthy_worker_lease_is_not_recovered_by_another_worker_starting()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        await using var db = new AppDbContext(options);
        var tenant = new Tenant("Lease tenant"); var user = new User(tenant.Id, "analyst", "Analyst", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "private-lab", user.Id, DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], ["mock-passive"], 10, 120, "approval-1", false);
        var job = new AgentJob(tenant.Id, scope.Id, user.Id, "mock-passive");
        var execution = new AgentExecution(job.Id, "MockNetworkDiscoveryAgent");
        db.Tenants.Add(tenant); db.Users.Add(user); db.TargetScopes.Add(scope); db.AgentJobs.Add(job); db.AgentExecutions.Add(execution);
        Assert.True(job.TryAcquireLease("worker-a", DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5)));
        execution.Start(); await db.SaveChangesAsync();
        var service = new ScanExecutionService(db, new TargetScopeValidator(new EmptyResolver()), new ConfigurationBuilder().Build(), NullLogger<ScanExecutionService>.Instance);

        await service.RecoverExpiredLeasesAsync(CancellationToken.None, tenant.Id);

        await db.Entry(job).ReloadAsync();
        Assert.Equal(ScanJobStatus.Running, job.Status);
        Assert.Equal("worker-a", job.LeaseOwnerWorkerId);
    }

    [Fact]
    public async Task Expired_leases_are_requeued_after_worker_restart()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        await using var db = new AppDbContext(options);
        var tenant = new Tenant("Recovery tenant"); var user = new User(tenant.Id, "analyst", "Analyst", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "private-lab", user.Id, DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], ["mock-passive"], 10, 120, "approval-1", false);
        var job = new AgentJob(tenant.Id, scope.Id, user.Id, "mock-passive");
        var execution = new AgentExecution(job.Id, "MockNetworkDiscoveryAgent");
        db.Tenants.Add(tenant); db.Users.Add(user); db.TargetScopes.Add(scope); db.AgentJobs.Add(job); db.AgentExecutions.Add(execution);
        var expiredLease = DateTimeOffset.UtcNow.AddMinutes(-2);
        Assert.True(job.TryAcquireLease("worker-a", expiredLease, TimeSpan.FromSeconds(1)));
        execution.Start(); await db.SaveChangesAsync();
        var service = new ScanExecutionService(db, new TargetScopeValidator(new StubResolver()), new ConfigurationBuilder().Build(), NullLogger<ScanExecutionService>.Instance);
        await service.RecoverExpiredLeasesAsync(CancellationToken.None, tenant.Id);
        await db.Entry(job).ReloadAsync();
        Assert.Equal(ScanJobStatus.Queued, job.Status);
        Assert.Equal(AgentExecutionStatus.Pending, (await db.AgentExecutions.SingleAsync()).Status);
    }

    [Fact]
    public async Task Duplicate_completed_delivery_is_idempotent()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        await using var db = new AppDbContext(options);
        var tenant = new Tenant("Duplicate tenant"); var user = new User(tenant.Id, "analyst", "Analyst", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "private", user.Id, DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], ["mock-passive"], 10, 120, "ticket", false);
        var job = new AgentJob(tenant.Id, scope.Id, user.Id, "mock-passive"); var execution = new AgentExecution(job.Id, "test");
        db.AddRange(tenant, user, scope, job, execution);
        Assert.True(job.TryAcquireLease("worker-a", DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1)));
        execution.Start(); job.Complete(); execution.Complete(); await db.SaveChangesAsync();
        var service = new ScanExecutionService(db, new TargetScopeValidator(new StubResolver()), new ConfigurationBuilder().Build(), NullLogger<ScanExecutionService>.Instance);

        var outcome = await service.ExecuteAsync(job.Id, CancellationToken.None, tenant.Id, "worker-b");

        Assert.Equal(ScanExecutionOutcome.AlreadyCompleted, outcome);
    }

    private sealed class StubResolver : IHostAddressResolver
    {
        public Task<IReadOnlyCollection<System.Net.IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyCollection<System.Net.IPAddress>>([]);
    }

    private sealed class EmptyResolver : IHostAddressResolver
    {
        public Task<IReadOnlyCollection<System.Net.IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyCollection<System.Net.IPAddress>>([]);
    }

    private static async Task<(Guid TenantId, Guid JobId, string WorkerId)> SeedInventoryJobAsync(DbContextOptions<AppDbContext> options, string workerId)
    {
        await using var db = new AppDbContext(options);
        var tenant = new Tenant($"inventory-{Guid.NewGuid():N}");
        var user = new User(tenant.Id, $"inventory-{Guid.NewGuid():N}", "Inventory", UserRole.SecurityAnalyst);
        var scope = new TargetScope(tenant.Id, "private-inventory", user.Id, DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], [InventoryOperationProfiles.NetworkInventoryPassive], 10, 120, "phase21.1-test", false);
        var worker = new WorkerRegistration(tenant.Id, workerId, "test", ["passive-inventory"]);
        worker.Heartbeat(0, 1);
        var job = new AgentJob(tenant.Id, scope.Id, user.Id, InventoryOperationProfiles.NetworkInventoryPassive);
        db.AddRange(tenant, user, scope, worker, job, new AgentExecution(job.Id, "ControlledInventoryAdapter"));
        await db.SaveChangesAsync();
        return (tenant.Id, job.Id, workerId);
    }

    private sealed class ControlledInventoryAdapter(IReadOnlyCollection<InventoryObservation> observations) : IPassiveInventoryAdapter
    {
        private readonly TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource CancellationObserved { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<IReadOnlyCollection<InventoryObservation>> CollectAsync(IReadOnlyCollection<AuthorizedInventoryTarget> targets, int requestsPerMinute, CancellationToken cancellationToken = default)
        {
            Started.TrySetResult();
            try { await release.Task.WaitAsync(cancellationToken); }
            catch (OperationCanceledException) { CancellationObserved.TrySetResult(); throw; }
            return observations;
        }

        public void Release() => release.TrySetResult();
    }

    private sealed class CancellationAfterFirstObservationAdapter(CancellationTokenSource cancellation, IReadOnlyCollection<InventoryObservation> observations) : IPassiveInventoryAdapter
    {
        public Task<IReadOnlyCollection<InventoryObservation>> CollectAsync(IReadOnlyCollection<AuthorizedInventoryTarget> targets, int requestsPerMinute, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyCollection<InventoryObservation>>(new CancellingCollection(cancellation, observations));
    }

    private sealed class CancellingCollection(CancellationTokenSource cancellation, IReadOnlyCollection<InventoryObservation> observations) : IReadOnlyCollection<InventoryObservation>
    {
        public int Count => observations.Count;
        public IEnumerator<InventoryObservation> GetEnumerator()
        {
            var index = 0;
            foreach (var observation in observations)
            {
                if (index++ == 1) cancellation.Cancel();
                yield return observation;
            }
        }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
