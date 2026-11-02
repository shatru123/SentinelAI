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
    public bool Enabled => options.ControlPlaneUrl is not null;
    public async Task RegisterAsync(CancellationToken cancellationToken)
    {
        if (!Enabled) return;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                using var response = await httpClient.PostAsJsonAsync("/api/v1/workers/register", new WorkerRegistrationRequest(options.Identity, options.Version, options.Capabilities), cancellationToken);
                response.EnsureSuccessStatusCode();
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
    public async Task HeartbeatAsync(int activeJobs, CancellationToken cancellationToken)
    {
        if (!Enabled) return;
        using var response = await httpClient.PostAsJsonAsync("/api/v1/workers/heartbeat", new WorkerHeartbeatRequest(options.Identity, activeJobs, options.Concurrency), cancellationToken);
        response.EnsureSuccessStatusCode();
    }
}

public sealed class WorkerHeartbeatService(WorkerControlPlaneClient controlPlane, WorkerActivityTracker activity, ILogger<WorkerHeartbeatService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!controlPlane.Enabled) { logger.LogInformation("Worker control-plane registration is disabled; broker authentication remains required in production."); return; }
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await controlPlane.HeartbeatAsync(activity.ActiveJobs, stoppingToken); }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested) { logger.LogWarning(exception, "Worker heartbeat failed; retrying after recovery interval."); }
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
        await using (var recoveryScope = scopeFactory.CreateAsyncScope())
            await recoveryScope.ServiceProvider.GetRequiredService<ScanExecutionService>().RecoverInterruptedJobsAsync(stoppingToken, options.TenantId);

        if (options.TenantId is null) throw new InvalidOperationException("A worker tenant assignment is required in production.");
        var cancellationListener = ListenForCancellationsAsync(options.Identity, stoppingToken);
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

    private async Task ListenForCancellationsAsync(string workerIdentity, CancellationToken cancellationToken)
    {
        await foreach (var jobId in queue.ReadCancellationsAsync(workerIdentity, cancellationToken))
        {
            logger.LogInformation("Cancellation signal received for job {JobId}.", jobId);
            cancellationRegistry.Cancel(jobId);
        }
    }

    private async Task ProcessDeliveryAsync(ScanJobDelivery delivery, SemaphoreSlim gate, CancellationToken stoppingToken)
    {
        var tracked = false;
        try
        {
            if (delivery.TenantId != options.TenantId) { logger.LogError("Worker {Identity} received a cross-tenant job {JobId}; dead-lettering without acknowledgement.", options.Identity, delivery.JobId); await delivery.RejectAsync(false, CancellationToken.None); return; }
            var jobToken = cancellationRegistry.Register(delivery.JobId, stoppingToken);
            activity.Increment(); tracked = true;
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
                await scope.ServiceProvider.GetRequiredService<ScanExecutionService>().RequeueOrFailAsync(delivery.JobId, delivery.Attempt + 1, options.MaxAttempts, exception.Message, CancellationToken.None);
            }
            catch (Exception persistenceException) { logger.LogError(persistenceException, "Could not persist failure state for job {JobId}.", delivery.JobId); }
            await delivery.RejectAsync(delivery.Attempt + 1 < options.MaxAttempts, CancellationToken.None);
        }
        finally
        {
            cancellationRegistry.Remove(delivery.JobId);
            if (tracked) activity.Decrement();
            gate.Release();
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
    public Guid? TenantId { get; }
    public WorkerOptions(IConfiguration configuration)
    {
        var url = configuration["Worker:ControlPlaneUrl"];
        Identity = configuration["Worker:Identity"]?.Trim() ?? Environment.GetEnvironmentVariable("HOSTNAME") ?? $"worker-{Guid.NewGuid():N}";
        ControlPlaneUrl = string.IsNullOrWhiteSpace(url) ? null : url.TrimEnd('/');
        Concurrency = Math.Clamp(configuration.GetValue("Worker:Concurrency", 2), 1, 32);
        MaxAttempts = Math.Clamp(configuration.GetValue("RabbitMQ:MaxAttempts", 3), 1, 20);
        TenantId = Guid.TryParse(configuration["Worker:TenantId"] ?? configuration["Authentication:WorkerTenantId"], out var tenantId) ? tenantId : null;
    }
}
