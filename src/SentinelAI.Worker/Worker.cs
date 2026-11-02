using System.Diagnostics.Metrics;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SentinelAI.Application;
using SentinelAI.Contracts;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;

namespace SentinelAI.Worker;

public sealed class WorkerControlPlaneClient(HttpClient httpClient, WorkerOptions options, ILogger<WorkerControlPlaneClient> logger)
{
    private int healthy;
    public bool Enabled => options.ControlPlaneUrl is not null;
    public bool IsHealthy => !Enabled || Volatile.Read(ref healthy) == 1;
    public async Task RegisterAsync(CancellationToken cancellationToken)
    {
        if (!Enabled) return;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                using var response = await httpClient.PostAsJsonAsync("/api/v1/workers/register", new WorkerRegistrationRequest(options.Identity, options.Version, options.Capabilities, options.Concurrency), cancellationToken);
                response.EnsureSuccessStatusCode();
                Volatile.Write(ref healthy, 1);
                logger.LogInformation("Worker {Identity} registered with the control plane.", options.Identity);
                return;
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                logger.LogWarning(exception, "Worker registration failed; retrying after recovery interval.");
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
            }
        }
    }
    public async Task HeartbeatAsync(int activeJobs, DateTimeOffset? lastJobStartedAt, DateTimeOffset? lastJobCompletedAt, CancellationToken cancellationToken)
    {
        if (!Enabled) return;
        using var response = await httpClient.PostAsJsonAsync("/api/v1/workers/heartbeat", new WorkerHeartbeatRequest(options.Identity, activeJobs, options.Concurrency, lastJobStartedAt, lastJobCompletedAt), cancellationToken);
        response.EnsureSuccessStatusCode();
        Volatile.Write(ref healthy, 1);
    }
    public void MarkUnhealthy() => Volatile.Write(ref healthy, 0);
}

public sealed class WorkerHeartbeatService(WorkerControlPlaneClient controlPlane, WorkerActivityTracker activity, ILogger<WorkerHeartbeatService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!controlPlane.Enabled) { logger.LogInformation("Worker control-plane registration is disabled; broker authentication remains required in production."); return; }
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await controlPlane.HeartbeatAsync(activity.ActiveJobs, activity.LastJobStartedAt, activity.LastJobCompletedAt, stoppingToken); }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested) { controlPlane.MarkUnhealthy(); logger.LogWarning(exception, "Worker heartbeat failed; retrying after recovery interval."); }
            await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
        }
    }
}

public sealed class Worker(ILogger<Worker> logger, IScanJobQueue queue, IServiceScopeFactory scopeFactory, WorkerCancellationRegistry cancellationRegistry, WorkerActivityTracker activity, WorkerControlPlaneClient controlPlane, WorkerOptions options) : BackgroundService
{
    private static readonly Meter Meter = new("SentinelAI.Jobs");
    private static readonly Counter<long> CompletedJobs = Meter.CreateCounter<long>("sentinelai.jobs.completed");
    private static readonly Counter<long> FailedJobs = Meter.CreateCounter<long>("sentinelai.jobs.failed");
    private readonly List<Task> running = [];

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("SentinelAI worker {Identity} starting with bounded concurrency {Concurrency}. Active network probing is disabled.", options.Identity, options.Concurrency);
        await controlPlane.RegisterAsync(stoppingToken);
        if (options.TenantId is null) throw new InvalidOperationException("A worker tenant assignment is required in production.");
        await using (var recoveryScope = scopeFactory.CreateAsyncScope())
            await recoveryScope.ServiceProvider.GetRequiredService<ScanExecutionService>().RecoverExpiredLeasesAsync(stoppingToken, options.TenantId);

        var cancellationListener = ListenForCancellationsAsync(options.TenantId.Value, options.Identity, stoppingToken);
        var gate = new SemaphoreSlim(options.Concurrency, options.Concurrency);
        try
        {
            await foreach (var delivery in queue.ReadAllAsync(options.TenantId, options.Identity, stoppingToken))
            {
                await gate.WaitAsync(stoppingToken);
                var task = ProcessDeliveryAsync(delivery, gate, stoppingToken);
                running.Add(task);
                _ = task.ContinueWith(completed => running.Remove(completed), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            try { await Task.WhenAll(running); } catch (Exception exception) { logger.LogWarning(exception, "One or more jobs ended during worker shutdown."); }
            try { await cancellationListener; } catch (OperationCanceledException) { }
            gate.Dispose();
        }
    }

    private async Task ListenForCancellationsAsync(Guid tenantId, string workerIdentity, CancellationToken cancellationToken)
    {
        await foreach (var jobId in queue.ReadCancellationsAsync(tenantId, workerIdentity, cancellationToken))
        {
            logger.LogInformation("Cancellation signal received for job {JobId}.", jobId);
            cancellationRegistry.Cancel(jobId);
        }
    }

    private async Task ProcessDeliveryAsync(ScanJobDelivery delivery, SemaphoreSlim gate, CancellationToken stoppingToken)
    {
        var tracked = false;
        CancellationTokenSource? leaseStop = null;
        Task? leaseRenewal = null;
        try
        {
            if (delivery.TenantId != options.TenantId) { logger.LogError("Worker {Identity} received a cross-tenant job {JobId}; dead-lettering without acknowledgement.", options.Identity, delivery.JobId); await delivery.RejectAsync(false, CancellationToken.None); return; }
            if (!controlPlane.IsHealthy) { logger.LogWarning("Worker {Identity} is not healthy; retrying job {JobId} without processing it.", options.Identity, delivery.JobId); await delivery.RejectAsync(true, CancellationToken.None); return; }
            var jobToken = cancellationRegistry.Register(delivery.JobId, stoppingToken);
            activity.Increment(); tracked = true;
            leaseStop = CancellationTokenSource.CreateLinkedTokenSource(jobToken, stoppingToken);
            leaseRenewal = RenewLeaseLoopAsync(delivery.JobId, options.Identity, leaseStop.Token, stoppingToken);
            await using var scope = scopeFactory.CreateAsyncScope();
            var outcome = await scope.ServiceProvider.GetRequiredService<ScanExecutionService>().ExecuteAsync(delivery.JobId, jobToken, options.TenantId, options.Identity);
            if (outcome is ScanExecutionOutcome.Missing or ScanExecutionOutcome.Unauthorized)
            {
                logger.LogError("Worker {Identity} could not authorize job {JobId} ({Outcome}); dead-lettering without acknowledgement.", options.Identity, delivery.JobId, outcome);
                await delivery.RejectAsync(false, CancellationToken.None);
                return;
            }
            await delivery.AcknowledgeAsync(stoppingToken);
            if (outcome == ScanExecutionOutcome.Completed) CompletedJobs.Add(1);
            if (outcome is ScanExecutionOutcome.AlreadyCompleted or ScanExecutionOutcome.AlreadyRunning or ScanExecutionOutcome.ClaimedByAnotherWorker)
                logger.LogDebug("Duplicate or already-owned job {JobId} acknowledged with outcome {Outcome}.", delivery.JobId, outcome);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            await delivery.RejectAsync(true, CancellationToken.None);
        }
        catch (Exception exception)
        {
            FailedJobs.Add(1);
            logger.LogError(exception, "Worker failed job {JobId} on attempt {Attempt}.", delivery.JobId, delivery.Attempt);
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var owned = await scope.ServiceProvider.GetRequiredService<ScanExecutionService>().RequeueOrFailAsync(delivery.JobId, options.Identity, delivery.Attempt + 1, options.MaxAttempts, exception.Message, CancellationToken.None);
                if (!owned) { await delivery.AcknowledgeAsync(CancellationToken.None); return; }
            }
            catch (Exception persistenceException) { logger.LogError(persistenceException, "Could not persist failure state for job {JobId}.", delivery.JobId); }
            await delivery.RejectAsync(delivery.Attempt + 1 < options.MaxAttempts, CancellationToken.None);
        }
        finally
        {
            if (leaseStop is not null)
            {
                leaseStop.Cancel();
                if (leaseRenewal is not null) try { await leaseRenewal; } catch (OperationCanceledException) { }
                leaseStop.Dispose();
            }
            cancellationRegistry.Remove(delivery.JobId);
            if (tracked) activity.Decrement();
            gate.Release();
        }
    }

    private async Task RenewLeaseLoopAsync(Guid jobId, string workerIdentity, CancellationToken jobToken, CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Clamp(options.LeaseRenewalSeconds, 2, 300));
        try
        {
            while (!jobToken.IsCancellationRequested && !stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(interval, jobToken);
                await using var scope = scopeFactory.CreateAsyncScope();
                if (!await scope.ServiceProvider.GetRequiredService<ScanExecutionService>().RenewLeaseAsync(jobId, workerIdentity, stoppingToken))
                {
                    cancellationRegistry.Cancel(jobId);
                    return;
                }
            }
        }
        catch (OperationCanceledException) when (jobToken.IsCancellationRequested || stoppingToken.IsCancellationRequested) { }
        catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
        {
            cancellationRegistry.Cancel(jobId);
            logger.LogWarning(exception, "Lease renewal failed for job {JobId}; execution cancellation was requested.", jobId);
        }
    }
}

public sealed class WorkerOptions
{
    public string Identity { get; }
    public string Version { get; } = typeof(Worker).Assembly.GetName().Version?.ToString() ?? "1.1";
    public IReadOnlyCollection<string> Capabilities { get; } = ["scope-validation", "passive-mock", "cancellation", "bounded-concurrency"];
    public string? ControlPlaneUrl { get; }
    public int Concurrency { get; }
    public int MaxAttempts { get; }
    public int LeaseDurationSeconds { get; }
    public int LeaseRenewalSeconds { get; }
    public Guid? TenantId { get; }
    public WorkerOptions(IConfiguration configuration)
    {
        var url = configuration["Worker:ControlPlaneUrl"];
        Identity = configuration["Worker:Identity"]?.Trim() ?? Environment.GetEnvironmentVariable("HOSTNAME") ?? $"worker-{Guid.NewGuid():N}";
        ControlPlaneUrl = string.IsNullOrWhiteSpace(url) ? null : url.TrimEnd('/');
        Concurrency = Math.Clamp(configuration.GetValue("Worker:Concurrency", 2), 1, 32);
        MaxAttempts = Math.Clamp(configuration.GetValue("RabbitMQ:MaxAttempts", 3), 1, 20);
        LeaseDurationSeconds = Math.Clamp(configuration.GetValue("Worker:LeaseDurationSeconds", 60), 10, 3600);
        LeaseRenewalSeconds = Math.Clamp(configuration.GetValue("Worker:LeaseRenewalSeconds", 15), 2, 300);
        if (LeaseRenewalSeconds >= LeaseDurationSeconds / 2) throw new InvalidOperationException("Worker lease renewal interval must be less than half of the lease duration.");
        TenantId = Guid.TryParse(configuration["Worker:TenantId"] ?? configuration["Authentication:WorkerTenantId"], out var tenantId) ? tenantId : null;
    }
}
