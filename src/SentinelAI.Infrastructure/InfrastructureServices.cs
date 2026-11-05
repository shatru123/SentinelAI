using Amazon;
using Amazon.S3;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using SentinelAI.Agent.Network;
using SentinelAI.Agent.Vulnerability;
using SentinelAI.Application;
using SentinelAI.Domain;
using SentinelAI.Security.Policy;

namespace SentinelAI.Infrastructure;

public static class InfrastructureServices
{
    public static IServiceCollection AddSentinelInfrastructure(this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        Action<DbContextOptionsBuilder> configureDb = options =>
        {
            var provider = configuration["Database:Provider"] ?? (environment.IsDevelopment() ? "InMemory" : "Postgres");
            if (provider.Equals("InMemory", StringComparison.OrdinalIgnoreCase)) options.UseInMemoryDatabase(configuration["Database:InMemoryName"] ?? "sentinelai");
            else options.UseNpgsql(configuration.GetConnectionString("SentinelAI") ?? "Host=localhost;Database=sentinelai;Username=sentinelai;Password=sentinelai");
        };
        services.AddDbContext<AppDbContext>(configureDb, ServiceLifetime.Scoped, ServiceLifetime.Singleton);
        services.AddDbContextFactory<AppDbContext>(configureDb);
        services.AddSingleton<IAppDbContextFactory, DefaultAppDbContextFactory>();
        services.AddScoped<IAppDbContext>(sp => sp.GetRequiredService<AppDbContext>());
        services.AddSingleton<IHostAddressResolver, SystemHostAddressResolver>();
        services.AddScoped<ITargetScopeValidator, TargetScopeValidator>();
        services.AddScoped<ScanExecutionService>();
        services.AddScoped<IWebAssessmentEngine, WebAssessmentEngine>();
        services.AddScoped<IHtmlReportGenerator, HtmlReportGenerator>();
        services.AddScoped<VulnerabilityIntelligenceSyncService>();
        services.AddHttpClient<NvdCveFeedClient>(client =>
        {
            NvdCveFeedClient.Configure(client);
            var apiKey = configuration["NVD_API_KEY"] ?? configuration["Nvd:ApiKey"];
            if (!string.IsNullOrWhiteSpace(apiKey))
                client.DefaultRequestHeaders.TryAddWithoutValidation("apiKey", apiKey);
        });
        services.AddHttpClient<CisaKevFeedClient>(client => CisaKevFeedClient.Configure(client));
        services.AddHttpClient<FirstEpssFeedClient>(client => FirstEpssFeedClient.Configure(client));
        services.AddScoped<IScreenshotCaptureService, PlaywrightScreenshotCaptureService>();
        if (string.Equals(configuration["Artifacts:Provider"], "S3", StringComparison.OrdinalIgnoreCase))
        {
            services.AddSingleton<IAmazonS3>(_ =>
            {
                var region = configuration["Artifacts:S3:Region"]
                    ?? throw new InvalidOperationException("Artifacts:S3:Region is required for S3 storage.");
                var clientConfiguration = new AmazonS3Config
                {
                    RegionEndpoint = RegionEndpoint.GetBySystemName(region),
                    ForcePathStyle = configuration.GetValue("Artifacts:S3:ForcePathStyle", false)
                };
                var serviceUrl = configuration["Artifacts:S3:ServiceUrl"];
                if (!string.IsNullOrWhiteSpace(serviceUrl))
                    clientConfiguration.ServiceURL = serviceUrl;
                return new AmazonS3Client(clientConfiguration);
            });
            services.AddSingleton<S3AssessmentArtifactStore>();
            services.AddSingleton<IAssessmentArtifactStore>(sp => sp.GetRequiredService<S3AssessmentArtifactStore>());
            services.AddSingleton<IAssessmentArtifactStoreReadiness>(sp => sp.GetRequiredService<S3AssessmentArtifactStore>());
        }
        else
        {
            services.AddSingleton<FileSystemAssessmentArtifactStore>();
            services.AddSingleton<IAssessmentArtifactStore>(sp => sp.GetRequiredService<FileSystemAssessmentArtifactStore>());
            services.AddSingleton<IAssessmentArtifactStoreReadiness>(sp => sp.GetRequiredService<FileSystemAssessmentArtifactStore>());
        }
        services.AddHostedService<AssessmentArtifactCleanupService>();
        services.AddSingleton<IPassiveInventoryAdapter, PassiveNetworkInventoryAdapter>();
        services.AddSingleton<WorkerCancellationRegistry>();
        services.AddSingleton<WorkerActivityTracker>();

        var messagingMode = configuration["Messaging:Mode"] ?? (environment.IsDevelopment() ? "InMemory" : "RabbitMq");
        if (messagingMode.Equals("RabbitMq", StringComparison.OrdinalIgnoreCase))
        {
            services.AddSingleton<RabbitMqConnectionProvider>();
            services.AddSingleton<RabbitMqScanJobQueue>();
            services.AddSingleton<IScanJobQueue>(sp => sp.GetRequiredService<RabbitMqScanJobQueue>());
            if (configuration.GetValue("Messaging:RunOutboxDispatcher", false)) services.AddHostedService<OutboxDispatcher>();
        }
        else
        {
            services.AddSingleton<IScanJobQueue, InMemoryScanJobQueue>();
            if (environment.IsDevelopment() && configuration.GetValue("Worker:RunInProcess", false))
                services.AddHostedService<ScanJobProcessor>();
        }
        return services;
    }
}

public sealed class DefaultAppDbContextFactory : IAppDbContextFactory
{
    private readonly Func<IAppDbContext> create;
    public DefaultAppDbContextFactory(IDbContextFactory<AppDbContext> factory) => create = () => factory.CreateDbContext();
    public DefaultAppDbContextFactory(Func<IAppDbContext> create) => this.create = create;
    public IAppDbContext CreateDbContext() => create();
}

public sealed class AssessmentArtifactCleanupService(
    IAssessmentArtifactStore artifacts,
    IServiceScopeFactory scopeFactory,
    ILogger<AssessmentArtifactCleanupService> logger) : BackgroundService
{
    private static readonly TimeSpan StagedGracePeriod = TimeSpan.FromHours(24);
    private static readonly TimeSpan PublishedGracePeriod = TimeSpan.FromHours(48);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        do
        {
            try { await RunCleanupCycleAsync(stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception exception) { logger.LogWarning(exception, "Assessment artifact cleanup failed."); }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    public async Task<int> RunCleanupCycleAsync(CancellationToken cancellationToken, TimeSpan? stagedGrace = null, TimeSpan? publishedGrace = null)
    {
        var now = DateTimeOffset.UtcNow;
        var stagedCleaned = await artifacts.CleanupStagedReportsAsync(now - (stagedGrace ?? StagedGracePeriod), cancellationToken);

        var publishedReconciled = 0;
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<IAppDbContext>();

            var completedReportKeys = await db.WebAssessments.AsNoTracking()
                .Where(x => x.Status == WebAssessmentStatus.Completed && x.ReportStorageKey != null)
                .Select(x => x.ReportStorageKey!)
                .ToListAsync(cancellationToken);

            var activeAssessmentIds = await db.WebAssessments.AsNoTracking()
                .Where(x => x.Status == WebAssessmentStatus.Running || x.Status == WebAssessmentStatus.Queued)
                .Select(x => x.Id)
                .ToListAsync(cancellationToken);

            var referencedSet = completedReportKeys.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var activeSet = activeAssessmentIds.Select(id => id.ToString("D")).ToHashSet(StringComparer.OrdinalIgnoreCase);

            publishedReconciled = await artifacts.ReconcilePublishedReportsAsync(
                now - (publishedGrace ?? PublishedGracePeriod),
                key =>
                {
                    if (referencedSet.Contains(key)) return Task.FromResult(true);
                    var segments = key.Split('/');
                    if (segments.Length >= 2 && activeSet.Contains(segments[1]))
                    {
                        return Task.FromResult(true);
                    }
                    return Task.FromResult(false);
                },
                cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Failed to query database for published report reconciliation; aborting reconciliation cycle.");
        }

        if (stagedCleaned > 0 || publishedReconciled > 0)
        {
            logger.LogInformation("Cleaned {StagedCount} abandoned staged report(s) and reconciled {PublishedCount} unreferenced published report(s).",
                stagedCleaned, publishedReconciled);
        }

        return stagedCleaned + publishedReconciled;
    }
}

public sealed class InMemoryScanJobQueue : IScanJobQueue, IImmediateScanJobQueue
{
    private readonly Channel<ScanJobMessage> jobs = Channel.CreateUnbounded<ScanJobMessage>();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<(Guid TenantId, string WorkerIdentity), Channel<Guid>> cancellations = new();
    public ValueTask EnqueueAsync(Guid jobId, CancellationToken cancellationToken = default) => EnqueueAsync(jobId, Guid.Empty, cancellationToken);
    public ValueTask EnqueueAsync(Guid jobId, Guid tenantId, CancellationToken cancellationToken = default) => jobs.Writer.WriteAsync(new ScanJobMessage(jobId, tenantId, null, 0), cancellationToken);
    public async IAsyncEnumerable<ScanJobDelivery> ReadAllAsync(Guid? tenantId = null, string? workerIdentity = null, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await foreach (var message in jobs.Reader.ReadAllAsync(cancellationToken))
        {
            if (tenantId is not null && message.TenantId != tenantId.Value) { await jobs.Writer.WriteAsync(message, cancellationToken); continue; }
            yield return new ScanJobDelivery(message.JobId, message.TenantId, message.WorkerIdentity, message.Attempt, static _ => ValueTask.CompletedTask, static (_, _) => ValueTask.CompletedTask);
        }
    }
    public ValueTask RequestCancellationAsync(Guid jobId, CancellationToken cancellationToken = default) => throw new InvalidOperationException("Tenant and worker identity are required for cancellation routing.");
    public ValueTask RequestCancellationAsync(Guid jobId, Guid tenantId, string workerIdentity, CancellationToken cancellationToken = default)
        => GetCancellationChannel(tenantId, workerIdentity).Writer.WriteAsync(jobId, cancellationToken);
    public IAsyncEnumerable<Guid> ReadCancellationsAsync(Guid tenantId, string workerIdentity, CancellationToken cancellationToken = default)
        => GetCancellationChannel(tenantId, workerIdentity).Reader.ReadAllAsync(cancellationToken);
    private Channel<Guid> GetCancellationChannel(Guid tenantId, string workerIdentity)
        => cancellations.GetOrAdd((tenantId, workerIdentity.Trim()), _ => Channel.CreateUnbounded<Guid>());
}

public sealed record ScanJobMessage(Guid JobId, Guid TenantId, string? WorkerIdentity, int Attempt);

public sealed class WorkerCancellationRegistry
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, CancellationTokenSource> tokens = new();
    public CancellationToken Register(Guid jobId, CancellationToken hostToken)
    {
        var source = CancellationTokenSource.CreateLinkedTokenSource(hostToken);
        var prior = tokens.AddOrUpdate(jobId, source, (_, old) => { old.Dispose(); return source; });
        if (!ReferenceEquals(prior, source)) source.Dispose();
        return source.Token;
    }
    public void Cancel(Guid jobId) { if (tokens.TryGetValue(jobId, out var source)) source.Cancel(); }
    public void Remove(Guid jobId) { if (tokens.TryRemove(jobId, out var source)) source.Dispose(); }
}

public sealed class WorkerActivityTracker
{
    private int activeJobs;
    public int ActiveJobs => Volatile.Read(ref activeJobs);
    public DateTimeOffset? LastJobStartedAt { get; private set; }
    public DateTimeOffset? LastJobCompletedAt { get; private set; }
    public void Increment() { LastJobStartedAt = DateTimeOffset.UtcNow; Interlocked.Increment(ref activeJobs); }
    public void Decrement() { LastJobCompletedAt = DateTimeOffset.UtcNow; Interlocked.Decrement(ref activeJobs); }
}

public enum ScanExecutionOutcome { Completed, Cancelled, Expired, AlreadyCompleted, AlreadyRunning, ClaimedByAnotherWorker, Unauthorized, Missing }

public sealed class ScanExecutionService(AppDbContext db, ITargetScopeValidator validator, IConfiguration configuration, ILogger<ScanExecutionService> logger, IPassiveInventoryAdapter? inventoryAdapter = null, IWebAssessmentEngine? webAssessmentEngine = null, IAssessmentArtifactStore? artifactStore = null)
{
    private static readonly ActivitySource ActivitySource = new("SentinelAI.Worker");
    private readonly int executionDelayMs = Math.Clamp(configuration.GetValue("Worker:ExecutionDelayMs", 50), 0, 60_000);
    private TimeSpan LeaseDuration => TimeSpan.FromSeconds(Math.Clamp(configuration.GetValue("Worker:LeaseDurationSeconds", 60), 10, 3600));
    private TimeSpan WorkerStaleAfter => TimeSpan.FromSeconds(Math.Clamp(configuration.GetValue("Worker:HeartbeatStaleSeconds", 45), 15, 3600));

    public async Task RecoverExpiredLeasesAsync(CancellationToken cancellationToken, Guid? authorizedTenantId = null)
    {
        var now = DateTimeOffset.UtcNow;
        var query = db.AgentJobs.Where(x => x.Status == ScanJobStatus.Running && (x.LeaseExpiresAt == null || x.LeaseExpiresAt <= now));
        if (authorizedTenantId is not null) query = query.Where(x => x.TenantId == authorizedTenantId.Value);
        var jobIds = await query.Select(x => x.Id).ToListAsync(cancellationToken);
        foreach (var jobId in jobIds)
        {
            try
            {
                var job = await db.AgentJobs.SingleOrDefaultAsync(x => x.Id == jobId, cancellationToken);
                if (job is null || job.Status != ScanJobStatus.Running || job.HasActiveLease(now)) continue;
                job.RecoverExpiredLease(now);
                var execution = await db.AgentExecutions.SingleOrDefaultAsync(x => x.AgentJobId == job.Id, cancellationToken);
                execution?.ResetForRetry();
                var webAssessment = await db.WebAssessments.SingleOrDefaultAsync(x => x.AgentJobId == job.Id, cancellationToken);
                webAssessment?.ResetForRetry();
                await db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateConcurrencyException exception)
            {
                db.ChangeTracker.Clear();
                logger.LogDebug(exception, "Concurrent lease recovery won for job {JobId}; continuing startup recovery.", jobId);
            }
        }
    }

    public Task RecoverInterruptedJobsAsync(CancellationToken cancellationToken, Guid? authorizedTenantId = null)
        => RecoverExpiredLeasesAsync(cancellationToken, authorizedTenantId);

    public async Task<bool> RenewLeaseAsync(Guid jobId, string workerIdentity, CancellationToken cancellationToken)
    {
        var job = await db.AgentJobs.SingleOrDefaultAsync(x => x.Id == jobId, cancellationToken);
        if (job is null || !job.RenewLease(workerIdentity, DateTimeOffset.UtcNow, LeaseDuration)) return false;
        try
        {
            await db.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateConcurrencyException)
        {
            db.ChangeTracker.Clear();
            return false;
        }
    }

    public async Task<ScanExecutionOutcome> ExecuteAsync(Guid jobId, CancellationToken cancellationToken, Guid? authorizedTenantId = null, string? workerIdentity = null)
    {
        using var activity = ActivitySource.StartActivity("sentinelai.job.execute");
        activity?.SetTag("sentinelai.job.id", jobId);
        var job = await db.AgentJobs.SingleOrDefaultAsync(x => x.Id == jobId, cancellationToken);
        if (job is null) return ScanExecutionOutcome.Missing;
        if (authorizedTenantId is not null && job.TenantId != authorizedTenantId.Value) return ScanExecutionOutcome.Unauthorized;
        if (job.Status is ScanJobStatus.Completed or ScanJobStatus.Failed) return ScanExecutionOutcome.AlreadyCompleted;
        if (job.Status == ScanJobStatus.Cancelled) return ScanExecutionOutcome.Cancelled;
        if (job.Status == ScanJobStatus.Expired) return ScanExecutionOutcome.Expired;
        if (job.ExpiresAt <= DateTimeOffset.UtcNow) { job.Expire(); await db.SaveChangesAsync(cancellationToken); return ScanExecutionOutcome.Expired; }
        var now = DateTimeOffset.UtcNow;
        if (job.Status == ScanJobStatus.Running)
        {
            if (job.HasActiveLease(now))
                return string.Equals(job.LeaseOwnerWorkerId, workerIdentity, StringComparison.Ordinal) ? ScanExecutionOutcome.AlreadyRunning : ScanExecutionOutcome.ClaimedByAnotherWorker;
            job.RecoverExpiredLease(now);
        }
        var effectiveWorkerIdentity = string.IsNullOrWhiteSpace(workerIdentity) ? "in-process" : workerIdentity.Trim();
        IReadOnlyCollection<string> workerCapabilities = [];
        IReadOnlyCollection<string>? workerPrivateNetworkRanges = null;
        if (workerIdentity is not null)
        {
            var worker = await db.Workers.AsNoTracking().SingleOrDefaultAsync(x => x.TenantId == job.TenantId && x.Identity == workerIdentity, cancellationToken);
            workerCapabilities = worker?.Capabilities ?? [];
            workerPrivateNetworkRanges = worker?.ApprovedPrivateNetworkRanges;
            if (WebAssessmentOperationProfiles.IsWeb(job.OperationProfile))
            {
                var routeScope = await db.TargetScopes.AsNoTracking().SingleOrDefaultAsync(x => x.Id == job.ScopeId && x.TenantId == job.TenantId, cancellationToken);
                if (routeScope?.WebHostingMode == WebHostingMode.Private &&
                    (!string.Equals(routeScope.PrivateWorkerIdentity, workerIdentity, StringComparison.Ordinal) || !workerCapabilities.Contains("private-web-assessment", StringComparer.OrdinalIgnoreCase)))
                    return ScanExecutionOutcome.Unauthorized;
            }
            var requiredCapability = WebAssessmentOperationProfiles.IsWeb(job.OperationProfile)
                ? "web-assessment"
                : job.OperationProfile.Equals(InventoryOperationProfiles.NetworkInventoryPassive, StringComparison.OrdinalIgnoreCase) ? "passive-inventory" : "passive-mock";
            if (worker is null || !worker.IsHealthyForAdmission(now, WorkerStaleAfter) || !worker.Capabilities.Contains(requiredCapability, StringComparer.OrdinalIgnoreCase)) return ScanExecutionOutcome.Unauthorized;
        }
        if (!job.TryAcquireLease(effectiveWorkerIdentity, now, LeaseDuration))
        {
            if (job.Status == ScanJobStatus.Cancelled) return ScanExecutionOutcome.Cancelled;
            if (job.Status is ScanJobStatus.Completed or ScanJobStatus.Failed) return ScanExecutionOutcome.AlreadyCompleted;
            if (job.Status == ScanJobStatus.Running) return ScanExecutionOutcome.ClaimedByAnotherWorker;
            return ScanExecutionOutcome.AlreadyRunning;
        }

        var execution = await db.AgentExecutions.SingleAsync(x => x.AgentJobId == job.Id, cancellationToken);
        if (execution.Status != AgentExecutionStatus.Pending)
        {
            if (execution.Status is AgentExecutionStatus.Completed or AgentExecutionStatus.Cancelled) return ScanExecutionOutcome.AlreadyCompleted;
            execution.ResetForRetry();
        }
        execution.Start();
        var scopeDefinition = await db.TargetScopes.SingleAsync(x => x.Id == job.ScopeId && x.TenantId == job.TenantId, cancellationToken);
        var initialScopeFingerprint = scopeDefinition.GetAuthorizationFingerprint();
        try { await db.SaveChangesAsync(cancellationToken); }
        catch (DbUpdateConcurrencyException)
        {
            db.ChangeTracker.Clear();
            return ScanExecutionOutcome.ClaimedByAnotherWorker;
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(scopeDefinition.MaxExecutionSeconds));
        string? generatedReportKey = null;
        Guid? generatedReportAssessmentId = null;
        try
        {
            if (WebAssessmentOperationProfiles.IsWeb(job.OperationProfile))
            {
                if (webAssessmentEngine is null) throw new InvalidOperationException("Web assessment execution is not configured.");
                var assessment = await db.WebAssessments.SingleAsync(x => x.AgentJobId == job.Id && x.TenantId == job.TenantId, timeout.Token);
                generatedReportAssessmentId = assessment.Id;
                var result = await webAssessmentEngine.ExecuteAsync(assessment, job, scopeDefinition, effectiveWorkerIdentity, workerCapabilities, workerPrivateNetworkRanges,
                    (activeDb, token) => HasActiveLeaseAsync(activeDb, job.Id, effectiveWorkerIdentity, token), timeout.Token,
                    (activeDb, token) => GetLiveWebWorkerAuthorizationAsync(activeDb, job.TenantId, effectiveWorkerIdentity, scopeDefinition, WorkerStaleAfter, token));
                generatedReportKey = result.ReportStorageKey;
                await db.Entry(job).ReloadAsync(timeout.Token);
                await db.Entry(execution).ReloadAsync(timeout.Token);
                await db.Entry(assessment).ReloadAsync(timeout.Token);
                if (!job.IsLeaseOwnedBy(effectiveWorkerIdentity, DateTimeOffset.UtcNow))
                {
                    await DiscardGeneratedReportAsync();
                    return ScanExecutionOutcome.ClaimedByAnotherWorker;
                }
                if (job.IsCancellationRequested || job.Status == ScanJobStatus.Cancelled)
                {
                    await DiscardGeneratedReportAsync();
                    execution.Cancel(); assessment.Cancel();
                    await db.SaveChangesAsync(CancellationToken.None);
                    return ScanExecutionOutcome.Cancelled;
                }
                if (string.IsNullOrWhiteSpace(result.ReportStorageKey)) throw new InvalidOperationException("A completed web assessment requires a persisted report artifact pointer.");
                await using var completionTransaction = await db.BeginTransactionAsync(timeout.Token);
                await db.Entry(job).ReloadAsync(timeout.Token);
                await db.Entry(execution).ReloadAsync(timeout.Token);
                await db.Entry(assessment).ReloadAsync(timeout.Token);
                if (!job.IsLeaseOwnedBy(effectiveWorkerIdentity, DateTimeOffset.UtcNow))
                {
                    await DiscardGeneratedReportAsync();
                    return ScanExecutionOutcome.ClaimedByAnotherWorker;
                }
                if (!await IsWebAssessmentStillAuthorizedAsync(job, assessment, effectiveWorkerIdentity, initialScopeFingerprint, timeout.Token))
                {
                    await DiscardGeneratedReportAsync();
                    execution.Cancel();
                    job.Cancel();
                    assessment.RevokeAuthorization();
                    db.AuditEvents.Add(new AuditEvent(job.TenantId, job.RequestedBy, "scan.authorization-revoked", nameof(AgentJob), job.Id,
                        "Worker or target authorization changed before report publication; the job was cancelled without publishing results."));
                    await db.SaveChangesAsync(CancellationToken.None);
                    await completionTransaction.CommitAsync(CancellationToken.None);
                    return ScanExecutionOutcome.Cancelled;
                }
                if (job.IsCancellationRequested || job.Status != ScanJobStatus.Running)
                {
                    await DiscardGeneratedReportAsync();
                    execution.Cancel(); assessment.Cancel();
                    await db.SaveChangesAsync(CancellationToken.None);
                    await completionTransaction.CommitAsync(CancellationToken.None);
                    return ScanExecutionOutcome.Cancelled;
                }
                execution.Complete();
                job.Complete();
                assessment.Complete(result.ReportStorageKey, result.EndpointCount);
                db.AuditEvents.Add(new AuditEvent(job.TenantId, job.RequestedBy, "web-assessment.completed", nameof(WebAssessment), assessment.Id, "Authorized web assessment completed with bounded, non-destructive checks."));
                await db.SaveChangesAsync(timeout.Token);
                await completionTransaction.CommitAsync(timeout.Token);
                generatedReportKey = null;
                generatedReportAssessmentId = null;
                return ScanExecutionOutcome.Completed;
            }
            var authorizedTargets = new List<AuthorizedInventoryTarget>(scopeDefinition.Targets.Count);
            foreach (var target in scopeDefinition.Targets)
            {
                timeout.Token.ThrowIfCancellationRequested();
                var persistedState = await db.AgentJobs.AsNoTracking().Where(x => x.Id == job.Id).Select(x => new { x.Status, x.CancellationRequestedAt, x.ExpiresAt, x.LeaseOwnerWorkerId, x.LeaseExpiresAt }).SingleAsync(timeout.Token);
                if (workerIdentity is not null && (persistedState.LeaseExpiresAt is null || persistedState.LeaseExpiresAt <= DateTimeOffset.UtcNow || !string.Equals(persistedState.LeaseOwnerWorkerId, workerIdentity, StringComparison.Ordinal)))
                    return ScanExecutionOutcome.ClaimedByAnotherWorker;
                if (persistedState.CancellationRequestedAt is not null || persistedState.Status == ScanJobStatus.Cancelled)
                {
                    job.Cancel(); execution.Cancel(); await db.SaveChangesAsync(CancellationToken.None); return ScanExecutionOutcome.Cancelled;
                }
                if (persistedState.ExpiresAt <= DateTimeOffset.UtcNow)
                {
                    job.Expire(); execution.Cancel(); await db.SaveChangesAsync(CancellationToken.None); return ScanExecutionOutcome.Expired;
                }
                var validation = await validator.ValidateExecutionAsync(scopeDefinition, job.TenantId, target.Kind, target.Value, job.OperationProfile, timeout.Token);
                if (!validation.IsValid) throw new ScopeValidationException(validation.Errors);
                if (executionDelayMs > 0) await Task.Delay(executionDelayMs, timeout.Token);
                authorizedTargets.Add(new AuthorizedInventoryTarget(target, validation.ValidatedTarget ?? throw new ScopeValidationException(["Execution validation did not produce a validated target."])));
            }

            if (workerIdentity is not null && !await HasActiveLeaseAsync(db, job.Id, workerIdentity, timeout.Token)) return ScanExecutionOutcome.ClaimedByAnotherWorker;
            var observations = await (inventoryAdapter ?? new PassiveNetworkInventoryAdapter()).CollectAsync(authorizedTargets, scopeDefinition.RequestsPerMinute, timeout.Token);
            if (workerIdentity is not null && !await HasActiveLeaseAsync(db, job.Id, workerIdentity, timeout.Token)) return ScanExecutionOutcome.ClaimedByAnotherWorker;
            foreach (var observation in observations)
            {
                timeout.Token.ThrowIfCancellationRequested();
                if (workerIdentity is not null && !await HasActiveLeaseAsync(db, job.Id, workerIdentity, timeout.Token)) return ScanExecutionOutcome.ClaimedByAnotherWorker;
                var asset = await db.Assets.SingleOrDefaultAsync(x => x.TenantId == job.TenantId && x.Address == observation.Address, timeout.Token);
                if (asset is null) { asset = new Asset(job.TenantId, scopeDefinition.Id, observation.Address, observation.Kind); db.Assets.Add(asset); }
                if (observation.IsOnline && observation.ReachabilityConfirmed) asset.RecordReachabilityConfirmation();
                else asset.RecordPassiveObservation();
                foreach (var service in observation.Services)
                {
                    if (service.Port is < 1 or > 65_535 || string.IsNullOrWhiteSpace(service.Protocol))
                        throw new ScopeValidationException(["Inventory service observations must contain a valid protocol and port."]);
                    var existingService = await db.AssetServices.SingleOrDefaultAsync(x => x.TenantId == job.TenantId && x.AssetId == asset.Id && x.Protocol == service.Protocol.Trim().ToLowerInvariant() && x.Port == service.Port, timeout.Token);
                    if (existingService is null) db.AssetServices.Add(new AssetService(job.TenantId, asset.Id, service.Protocol, service.Port, service.Name, service.Version));
                }
            }

            await using var inventoryTransaction = await db.BeginTransactionAsync(timeout.Token);
            await db.Entry(job).ReloadAsync(timeout.Token);
            if (workerIdentity is not null && !job.IsLeaseOwnedBy(workerIdentity, DateTimeOffset.UtcNow)) return ScanExecutionOutcome.ClaimedByAnotherWorker;
            if (job.IsCancellationRequested || job.Status == ScanJobStatus.Cancelled) { execution.Cancel(); await db.SaveChangesAsync(CancellationToken.None); await inventoryTransaction.CommitAsync(CancellationToken.None); return ScanExecutionOutcome.Cancelled; }
            if (job.ExpiresAt <= DateTimeOffset.UtcNow) { job.Expire(); execution.Cancel(); await db.SaveChangesAsync(CancellationToken.None); await inventoryTransaction.CommitAsync(CancellationToken.None); return ScanExecutionOutcome.Expired; }
            execution.Complete(); job.Complete();
            db.AuditEvents.Add(new AuditEvent(job.TenantId, job.RequestedBy, "scan.completed", nameof(AgentJob), job.Id, "Passive assessment completed; no active network probing was performed."));
            await db.SaveChangesAsync(timeout.Token);
            await inventoryTransaction.CommitAsync(timeout.Token);
            return ScanExecutionOutcome.Completed;
        }
        catch (WebAssessmentAuthorizationRevokedException)
        {
            await DiscardGeneratedReportAsync();
            await db.Entry(job).ReloadAsync(CancellationToken.None);
            await db.Entry(execution).ReloadAsync(CancellationToken.None);
            var webAssessment = await db.WebAssessments.SingleOrDefaultAsync(x => x.AgentJobId == job.Id && x.TenantId == job.TenantId, CancellationToken.None);
            if (job.Status is not (ScanJobStatus.Completed or ScanJobStatus.Failed)) job.Cancel();
            execution.Cancel();
            webAssessment?.RevokeAuthorization();
            db.AuditEvents.Add(new AuditEvent(job.TenantId, job.RequestedBy, "scan.authorization-revoked", nameof(AgentJob), job.Id,
                "Worker authorization was revoked during execution; the job was cancelled without publishing results."));
            await db.SaveChangesAsync(CancellationToken.None);
            return ScanExecutionOutcome.Cancelled;
        }
        catch (WebAssessmentLeaseLostException)
        {
            await DiscardGeneratedReportAsync();
            await db.Entry(job).ReloadAsync(CancellationToken.None);
            await db.Entry(execution).ReloadAsync(CancellationToken.None);
            var webAssessment = await db.WebAssessments.SingleOrDefaultAsync(x => x.AgentJobId == job.Id && x.TenantId == job.TenantId, CancellationToken.None);
            if (job.IsCancellationRequested || job.Status == ScanJobStatus.Cancelled)
            {
                execution.Cancel();
                webAssessment?.Cancel();
                await db.SaveChangesAsync(CancellationToken.None);
                return ScanExecutionOutcome.Cancelled;
            }
            return ScanExecutionOutcome.ClaimedByAnotherWorker;
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            await DiscardGeneratedReportAsync();
            await db.Entry(job).ReloadAsync(CancellationToken.None);
            DiscardPendingInventoryChanges();
            if (workerIdentity is not null && !job.IsLeaseOwnedBy(workerIdentity, DateTimeOffset.UtcNow)) return ScanExecutionOutcome.ClaimedByAnotherWorker;
            if (job.IsCancellationRequested || job.Status == ScanJobStatus.Cancelled)
            {
                execution.Cancel(); await db.SaveChangesAsync(CancellationToken.None); return ScanExecutionOutcome.Cancelled;
            }
            if (cancellationToken.IsCancellationRequested && DateTimeOffset.UtcNow < job.ExpiresAt)
            {
                if (workerIdentity is not null && !job.IsLeaseOwnedBy(workerIdentity, DateTimeOffset.UtcNow)) return ScanExecutionOutcome.ClaimedByAnotherWorker;
                job.ReleaseLeaseForRetry("Worker interruption; queued for retry."); execution.ResetForRetry(); await db.SaveChangesAsync(CancellationToken.None); return ScanExecutionOutcome.AlreadyRunning;
            }
            if (job.Status is ScanJobStatus.Queued or ScanJobStatus.Running)
            {
                var expiryReason = $"Execution duration limit ({scopeDefinition.MaxExecutionSeconds} seconds) was reached.";
                job.Expire();
                execution.Cancel();

                var webAssessment = await db.WebAssessments.SingleOrDefaultAsync(
                    x => x.AgentJobId == job.Id && x.TenantId == job.TenantId, CancellationToken.None);
                if (webAssessment is not null)
                {
                    webAssessment.Expire(expiryReason);
                    db.AuditEvents.Add(new AuditEvent(job.TenantId, job.RequestedBy, "web-assessment.expired",
                        nameof(WebAssessment), webAssessment.Id, expiryReason));
                }

                db.AuditEvents.Add(new AuditEvent(job.TenantId, job.RequestedBy, "scan.expired",
                    nameof(AgentJob), job.Id, expiryReason));
                await db.SaveChangesAsync(CancellationToken.None);
                return ScanExecutionOutcome.Expired;
            }
            return ScanExecutionOutcome.AlreadyRunning;
        }
        catch (Exception exception)
        {
            await DiscardGeneratedReportAsync();
            logger.LogWarning(exception, "Job {JobId} failed during execution.", jobId);
            throw;
        }

        async Task DiscardGeneratedReportAsync()
        {
            if (artifactStore is null || string.IsNullOrWhiteSpace(generatedReportKey)) return;
            var key = generatedReportKey;
            generatedReportKey = null;
            if (generatedReportAssessmentId is null) return;
            var assessmentId = generatedReportAssessmentId.Value;
            generatedReportAssessmentId = null;
            try { await artifactStore.DiscardReportAsync(job.TenantId, assessmentId, key, CancellationToken.None); }
            catch { logger.LogWarning("Unable to clean up an unpublished report artifact for job {JobId}.", job.Id); }
        }
    }

    private void DiscardPendingInventoryChanges()
    {
        foreach (var entry in db.ChangeTracker.Entries().Where(entry => entry.Entity is Asset or AssetService).ToList())
        {
            if (entry.State == EntityState.Added)
            {
                entry.State = EntityState.Detached;
                continue;
            }

            if (entry.State == EntityState.Modified)
            {
                entry.CurrentValues.SetValues(entry.OriginalValues);
                entry.State = EntityState.Unchanged;
            }
        }
    }

    private static async Task<bool> HasActiveLeaseAsync(IAppDbContext context, Guid jobId, string workerIdentity, CancellationToken cancellationToken)
        => await context.AgentJobs.AsNoTracking().AnyAsync(x => x.Id == jobId && x.Status == ScanJobStatus.Running && x.LeaseOwnerWorkerId == workerIdentity && x.LeaseExpiresAt > DateTimeOffset.UtcNow, cancellationToken);

    private static async Task<WorkerExecutionContext?> GetLiveWebWorkerAuthorizationAsync(IAppDbContext context, Guid tenantId, string workerIdentity, TargetScope scope, TimeSpan workerStaleAfter, CancellationToken cancellationToken)
    {
        var worker = await context.Workers.AsNoTracking().SingleOrDefaultAsync(x => x.TenantId == tenantId && x.Identity == workerIdentity, cancellationToken);
        if (worker is null || !worker.IsHealthyForAdmission(DateTimeOffset.UtcNow, workerStaleAfter) ||
            !worker.Capabilities.Contains(WebAssessmentCapabilities.WebAssessment, StringComparer.OrdinalIgnoreCase)) return null;
        if (scope.WebHostingMode == WebHostingMode.Private &&
            (!string.Equals(scope.PrivateWorkerIdentity, workerIdentity, StringComparison.Ordinal) ||
             !worker.Capabilities.Contains(WebAssessmentCapabilities.PrivateWebAssessment, StringComparer.OrdinalIgnoreCase) ||
             !worker.PrivateAssessmentApproved || worker.ApprovedPrivateNetworkRanges.Count == 0)) return null;
        return new WorkerExecutionContext(worker.Identity, worker.Capabilities.ToArray(), worker.ApprovedPrivateNetworkRanges.ToArray());
    }

    private async Task<bool> IsWebAssessmentStillAuthorizedAsync(AgentJob job, WebAssessment assessment, string workerIdentity, string initialScopeFingerprint, CancellationToken cancellationToken)
    {
        var worker = await db.Workers.AsNoTracking().SingleOrDefaultAsync(x => x.TenantId == job.TenantId && x.Identity == workerIdentity, cancellationToken);
        if (worker is null || !worker.IsHealthyForAdmission(DateTimeOffset.UtcNow, WorkerStaleAfter) ||
            !worker.Capabilities.Contains(WebAssessmentCapabilities.WebAssessment, StringComparer.OrdinalIgnoreCase)) return false;

        var scope = await db.TargetScopes.AsNoTracking().SingleOrDefaultAsync(x => x.Id == assessment.ScopeId && x.TenantId == job.TenantId, cancellationToken);
        if (scope is null || scope.ExpiresAt <= DateTimeOffset.UtcNow ||
            !string.Equals(initialScopeFingerprint, scope.GetAuthorizationFingerprint(), StringComparison.Ordinal)) return false;
        var currentWorker = new WorkerExecutionContext(worker.Identity, worker.Capabilities.ToArray(), worker.ApprovedPrivateNetworkRanges.ToArray());
        var validation = await validator.ValidateExecutionAsync(scope, job.TenantId, TargetKind.Web, assessment.TargetUrl, assessment.Profile, currentWorker, cancellationToken);
        return validation.IsValid && validation.ValidatedTarget is not null &&
            (scope.WebHostingMode != WebHostingMode.Private ||
             (scope.PrivateWorkerIdentity == workerIdentity && worker.PrivateAssessmentApproved &&
              worker.Capabilities.Contains(WebAssessmentCapabilities.PrivateWebAssessment, StringComparer.OrdinalIgnoreCase)));
    }

    public async Task<bool> RequeueOrFailAsync(Guid jobId, string expectedWorkerIdentity, int attempt, int maxAttempts, string reason, CancellationToken cancellationToken)
    {
        var job = await db.AgentJobs.SingleOrDefaultAsync(x => x.Id == jobId, cancellationToken);
        if (job is null || !job.IsLeaseOwnedBy(expectedWorkerIdentity, DateTimeOffset.UtcNow)) return false;
        var execution = await db.AgentExecutions.SingleOrDefaultAsync(x => x.AgentJobId == job.Id, cancellationToken);
        var webAssessment = await db.WebAssessments.SingleOrDefaultAsync(x => x.AgentJobId == job.Id && x.TenantId == job.TenantId, cancellationToken);
        if (attempt >= maxAttempts)
        {
            execution?.Fail(reason);
            webAssessment?.Fail(reason);
            job.Fail(reason);
        }
        else
        {
            job.ReleaseLeaseForRetry(reason);
            execution?.ResetForRetry();
            webAssessment?.ResetForRetry();
        }
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }
}

public sealed class ScanJobProcessor(
    IServiceScopeFactory scopeFactory,
    IScanJobQueue queue,
    WorkerCancellationRegistry cancellations,
    ILogger<ScanJobProcessor> logger) : BackgroundService
{
    private const string WorkerIdentity = "in-process";
    private const string WorkerVersion = "development";
    private static readonly string[] Capabilities =
        ["passive-mock", "passive-inventory", WebAssessmentCapabilities.WebAssessment];

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await using (var recoveryScope = scopeFactory.CreateAsyncScope())
        {
            try
            {
                await recoveryScope.ServiceProvider.GetRequiredService<ScanExecutionService>()
                    .RecoverExpiredLeasesAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "In-process worker startup recovery failed; queued work will still be processed.");
            }
        }

        await foreach (var delivery in queue.ReadAllAsync(cancellationToken: stoppingToken))
        {
            using var hostLinked = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            CancellationToken executionToken = default;
            CancellationTokenSource? maintenanceStop = null;
            Task? cancellationListener = null;
            Task? maintenance = null;

            try
            {
                await EnsureWorkerReadyAsync(delivery.TenantId, activeJobs: 1, stoppingToken);
                executionToken = cancellations.Register(delivery.JobId, hostLinked.Token);
                cancellationListener = ListenForCancellationsAsync(delivery.JobId, delivery.TenantId, hostLinked.Token);

                maintenanceStop = CancellationTokenSource.CreateLinkedTokenSource(executionToken);
                maintenance = MaintainWorkerPresenceAsync(delivery.JobId, delivery.TenantId, maintenanceStop.Token);

                await using var executionScope = scopeFactory.CreateAsyncScope();
                var outcome = await executionScope.ServiceProvider.GetRequiredService<ScanExecutionService>()
                    .ExecuteAsync(delivery.JobId, executionToken, delivery.TenantId, WorkerIdentity);

                if (outcome == ScanExecutionOutcome.Unauthorized)
                {
                    logger.LogError("In-process worker could not authorize job {JobId}.", delivery.JobId);
                    await MarkQueuedJobFailedAsync(delivery.JobId, delivery.TenantId,
                        "The local development worker could not authorize this job. Private web assessments require the separately enrolled private worker; use the Docker Compose worker for private targets.",
                        stoppingToken);
                }
                else if (outcome == ScanExecutionOutcome.Missing)
                {
                    logger.LogError("In-process worker received a delivery for missing job {JobId}.", delivery.JobId);
                }

                await delivery.AcknowledgeAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                await delivery.RejectAsync(true, CancellationToken.None);
                return;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "In-process worker failed job {JobId}.", delivery.JobId);
                try
                {
                    await using var failureScope = scopeFactory.CreateAsyncScope();
                    var persistedFailure = await failureScope.ServiceProvider.GetRequiredService<ScanExecutionService>()
                        .RequeueOrFailAsync(delivery.JobId, WorkerIdentity, 1, 1, exception.Message, CancellationToken.None);
                    if (!persistedFailure)
                    {
                        await MarkQueuedJobFailedAsync(delivery.JobId, delivery.TenantId, exception.Message, CancellationToken.None);
                    }
                    await delivery.AcknowledgeAsync(CancellationToken.None);
                }
                catch (Exception persistenceException)
                {
                    logger.LogError(persistenceException, "Could not persist the in-process failure state for job {JobId}.", delivery.JobId);
                    await delivery.RejectAsync(false, CancellationToken.None);
                }
            }
            finally
            {
                maintenanceStop?.Cancel();
                if (maintenance is not null)
                {
                    try { await maintenance; }
                    catch (OperationCanceledException) { }
                }

                cancellations.Remove(delivery.JobId);
                try { await EnsureWorkerReadyAsync(delivery.TenantId, activeJobs: 0, CancellationToken.None); }
                catch (Exception exception) { logger.LogWarning(exception, "Could not refresh the idle in-process worker heartbeat."); }

                hostLinked.Cancel();
                if (cancellationListener is not null)
                {
                    try { await cancellationListener; }
                    catch (OperationCanceledException) { }
                }
                maintenanceStop?.Dispose();
            }
        }
    }

    private async Task MarkQueuedJobFailedAsync(Guid jobId, Guid tenantId, string reason, CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<IAppDbContext>();
        var job = await db.AgentJobs.SingleOrDefaultAsync(
            item => item.Id == jobId && item.TenantId == tenantId, cancellationToken);
        if (job is null || job.Status != ScanJobStatus.Queued) return;

        job.Fail(reason);
        var execution = await db.AgentExecutions.SingleOrDefaultAsync(item => item.AgentJobId == jobId, cancellationToken);
        execution?.Fail(reason);
        var assessment = await db.WebAssessments.SingleOrDefaultAsync(
            item => item.AgentJobId == jobId && item.TenantId == tenantId, cancellationToken);
        assessment?.Fail(reason);
        db.AuditEvents.Add(new AuditEvent(tenantId, job.RequestedBy, "job.execution.failed",
            nameof(AgentJob), job.Id, reason));
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task EnsureWorkerReadyAsync(Guid tenantId, int activeJobs, CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<IAppDbContext>();
        var worker = await db.Workers.SingleOrDefaultAsync(
            item => item.TenantId == tenantId && item.Identity == WorkerIdentity, cancellationToken);

        if (worker is null)
        {
            worker = new WorkerRegistration(tenantId, WorkerIdentity, WorkerVersion, Capabilities);
            db.Workers.Add(worker);
        }
        else
        {
            // This reserved identity is managed only by the Development in-process host.
            // It deliberately never receives private-web-assessment capability.
            worker.ProvisionByAdministrator(WorkerVersion, Capabilities, []);
        }

        worker.Heartbeat(activeJobs, capacity: 1);
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task ListenForCancellationsAsync(Guid jobId, Guid tenantId, CancellationToken cancellationToken)
    {
        await foreach (var cancelledJobId in queue.ReadCancellationsAsync(tenantId, WorkerIdentity, cancellationToken))
        {
            if (cancelledJobId == jobId)
            {
                cancellations.Cancel(jobId);
                return;
            }
        }
    }

    private async Task MaintainWorkerPresenceAsync(Guid jobId, Guid tenantId, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(10));
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var execution = scope.ServiceProvider.GetRequiredService<ScanExecutionService>();
                if (!await execution.RenewLeaseAsync(jobId, WorkerIdentity, cancellationToken))
                {
                    logger.LogWarning("In-process worker lost the execution lease for job {JobId}; cancelling execution.", jobId);
                    cancellations.Cancel(jobId);
                    return;
                }

                var db = scope.ServiceProvider.GetRequiredService<IAppDbContext>();
                var worker = await db.Workers.SingleOrDefaultAsync(
                    item => item.TenantId == tenantId && item.Identity == WorkerIdentity, cancellationToken);
                if (worker is null || worker.Status == WorkerStatus.Disabled ||
                    !worker.Capabilities.Contains(WebAssessmentCapabilities.WebAssessment, StringComparer.OrdinalIgnoreCase))
                {
                    logger.LogWarning("In-process worker authorization changed while job {JobId} was running.", jobId);
                    cancellations.Cancel(jobId);
                    return;
                }

                worker.Heartbeat(activeJobs: 1, capacity: 1);
                await db.SaveChangesAsync(cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception exception)
        {
            logger.LogError(exception, "In-process worker lease/heartbeat maintenance failed for job {JobId}; cancelling execution.", jobId);
            cancellations.Cancel(jobId);
        }
    }
}

public sealed class RabbitMqConnectionProvider(IConfiguration configuration, ILogger<RabbitMqConnectionProvider> logger) : IAsyncDisposable
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private IConnection? connection;
    public async Task<IConnection> GetConnectionAsync(CancellationToken cancellationToken)
    {
        if (connection?.IsOpen == true) return connection;
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (connection?.IsOpen == true) return connection;
            var factory = new ConnectionFactory
            {
                HostName = configuration["RabbitMQ:Host"] ?? "localhost",
                Port = configuration.GetValue("RabbitMQ:Port", 5672),
                UserName = configuration["RabbitMQ:Username"] ?? "sentinelai",
                Password = configuration["RabbitMQ:Password"] ?? "sentinelai",
                VirtualHost = configuration["RabbitMQ:VirtualHost"] ?? "/",
                AutomaticRecoveryEnabled = true,
                TopologyRecoveryEnabled = true,
                NetworkRecoveryInterval = TimeSpan.FromSeconds(5),
                ClientProvidedName = configuration["RabbitMQ:ClientName"] ?? "sentinelai"
            };
            connection = await factory.CreateConnectionAsync(cancellationToken);
            logger.LogInformation("Connected to RabbitMQ as {ClientName}.", factory.ClientProvidedName);
            return connection;
        }
        finally { gate.Release(); }
    }
    public async ValueTask DisposeAsync()
    {
        if (connection is not null) await connection.DisposeAsync();
        gate.Dispose();
    }
}

public sealed class RabbitMqScanJobQueue(RabbitMqConnectionProvider provider, IConfiguration configuration, ILogger<RabbitMqScanJobQueue> logger) : IScanJobQueue
{
    private const string MainQueue = "sentinelai.scan.jobs";
    private const string RetryQueue = "sentinelai.scan.jobs.retry";
    private const string CancellationQueue = "sentinelai.scan.cancellations";
    private const string DeadExchange = "sentinelai.scan.jobs.dlx";
    private const string DeadQueue = "sentinelai.scan.jobs.dead";
    private const string Exchange = "";
    private static readonly ActivitySource ActivitySource = new("SentinelAI.RabbitMq");
    private int RetryDelayMs => Math.Clamp(configuration.GetValue("RabbitMQ:RetryDelayMs", 5000), 100, 300000);
    private int MaxAttempts => Math.Clamp(configuration.GetValue("RabbitMQ:MaxAttempts", 3), 1, 20);
    private ushort Prefetch => (ushort)Math.Clamp(configuration.GetValue("Worker:Concurrency", 2), 1, 32);

    public ValueTask EnqueueAsync(Guid jobId, CancellationToken cancellationToken = default) => EnqueueAsync(jobId, Guid.Empty, cancellationToken);
    public ValueTask EnqueueAsync(Guid jobId, Guid tenantId, CancellationToken cancellationToken = default)
        => PublishAsync(MainQueueFor(tenantId), new ScanJobMessage(jobId, tenantId, null, 0), 0, cancellationToken);

    public ValueTask RequestCancellationAsync(Guid jobId, CancellationToken cancellationToken = default)
        => PublishAsync(CancellationQueue, new ScanJobMessage(jobId, Guid.Empty, null, 0), 0, cancellationToken);
    public ValueTask RequestCancellationAsync(Guid jobId, Guid tenantId, string workerIdentity, CancellationToken cancellationToken = default)
    {
        if (tenantId == Guid.Empty || string.IsNullOrWhiteSpace(workerIdentity)) throw new ArgumentException("Tenant and exact worker identity are required for cancellation routing.");
        return PublishAsync(CancellationQueueFor(tenantId, workerIdentity), new ScanJobMessage(jobId, tenantId, workerIdentity, 0), 0, cancellationToken);
    }

    public async IAsyncEnumerable<ScanJobDelivery> ReadAllAsync(Guid? tenantId = null, string? workerIdentity = null, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (tenantId is null && string.IsNullOrWhiteSpace(workerIdentity))
        {
            await foreach (var delivery in ReadQueueAsync(MainQueue, null, cancellationToken: cancellationToken)) yield return delivery;
            yield break;
        }
        if (tenantId is null) throw new InvalidOperationException("A tenant must be provided for worker job consumption.");
        if (string.IsNullOrWhiteSpace(workerIdentity))
        {
            await foreach (var delivery in ReadQueueAsync(MainQueueFor(tenantId.Value), tenantId, cancellationToken: cancellationToken)) yield return delivery;
            yield break;
        }
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var merged = Channel.CreateUnbounded<ScanJobDelivery>();
        var readers = new[]
        {
            ReadQueueToChannelAsync(MainQueueFor(tenantId.Value), tenantId.Value, null, merged.Writer, linked.Token),
            ReadQueueToChannelAsync(MainQueueForWorker(tenantId.Value, workerIdentity!), tenantId.Value, workerIdentity, merged.Writer, linked.Token)
        };
        try
        {
            await foreach (var delivery in merged.Reader.ReadAllAsync(linked.Token)) yield return delivery;
        }
        finally
        {
            linked.Cancel();
            merged.Writer.TryComplete();
            try { await Task.WhenAll(readers); } catch (OperationCanceledException) { }
        }
    }

    public async IAsyncEnumerable<Guid> ReadCancellationsAsync(Guid tenantId, string workerIdentity, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (tenantId == Guid.Empty || string.IsNullOrWhiteSpace(workerIdentity)) throw new InvalidOperationException("A tenant and exact worker identity are required for cancellation consumption.");
        await foreach (var delivery in ReadQueueAsync(CancellationQueueFor(tenantId, workerIdentity), tenantId, workerIdentity, cancellationToken))
        {
            await delivery.AcknowledgeAsync(cancellationToken);
            yield return delivery.JobId;
        }
    }

    public async Task PublishOutboxAsync(OutboxMessage message, CancellationToken cancellationToken)
    {
        if (message.MessageType.Equals(OutboxMessageTypes.ScanJob, StringComparison.Ordinal))
        {
            var envelope = OutboxMessagePayload.Deserialize<OutboxJobEnvelope>(message.Payload);
            var queue = string.IsNullOrWhiteSpace(envelope.WorkerIdentity) ? MainQueueFor(envelope.TenantId) : MainQueueForWorker(envelope.TenantId, envelope.WorkerIdentity!);
            await PublishAsync(queue, new ScanJobMessage(envelope.JobId, envelope.TenantId, envelope.WorkerIdentity, 0), 0, cancellationToken);
        }
        else if (message.MessageType.Equals(OutboxMessageTypes.Cancellation, StringComparison.Ordinal))
        {
            var envelope = OutboxMessagePayload.Deserialize<OutboxCancellationEnvelope>(message.Payload);
            await PublishAsync(CancellationQueueFor(envelope.TenantId, envelope.WorkerIdentity), new ScanJobMessage(envelope.JobId, envelope.TenantId, envelope.WorkerIdentity, 0), 0, cancellationToken);
        }
        else throw new InvalidOperationException($"Unknown outbox message type '{message.MessageType}'.");
    }

    private async IAsyncEnumerable<ScanJobDelivery> ReadQueueAsync(string queue, Guid? expectedTenant, string? expectedWorkerIdentity = null, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var connection = await provider.GetConnectionAsync(cancellationToken);
        await using var channel = await connection.CreateChannelAsync(cancellationToken: cancellationToken);
        await DeclareTopologyAsync(channel, queue, cancellationToken);
        await channel.BasicQosAsync(0, Prefetch, false, cancellationToken);
        var deliveries = Channel.CreateUnbounded<BasicDeliverEventArgs>();
        var consumer = new AsyncEventingBasicConsumer(channel);
        consumer.ReceivedAsync += (_, args) => deliveries.Writer.WriteAsync(args).AsTask();
        var consumerTag = await channel.BasicConsumeAsync(queue, false, consumer, cancellationToken);
        var channelGate = new SemaphoreSlim(1, 1);
        try
        {
            await foreach (var args in deliveries.Reader.ReadAllAsync(cancellationToken))
            {
                var attempt = ReadAttempt(args.BasicProperties.Headers);
                var message = ParseMessage(args.Body.Span);
                var validTenant = expectedTenant is null || message.TenantId == expectedTenant.Value;
                var validWorker = expectedWorkerIdentity is null || string.Equals(message.WorkerIdentity, expectedWorkerIdentity, StringComparison.Ordinal);
                if (!validTenant || !validWorker)
                {
                    logger.LogError("Rejecting invalid routed message {JobId}; tenant or worker identity did not match the consumer.", message.JobId);
                    await RejectAsync(channel, channelGate, args.DeliveryTag, message, attempt, false, cancellationToken);
                    continue;
                }
                yield return new ScanJobDelivery(message.JobId, message.TenantId, message.WorkerIdentity, attempt,
                    ct => AcknowledgeAsync(channel, channelGate, args.DeliveryTag, ct),
                    (retry, ct) => RejectAsync(channel, channelGate, args.DeliveryTag, message, attempt, retry, ct));
            }
        }
        finally
        {
            deliveries.Writer.TryComplete();
            try { await channel.BasicCancelAsync(consumerTag, cancellationToken: CancellationToken.None); } catch (Exception exception) { logger.LogDebug(exception, "RabbitMQ consumer cancellation failed during shutdown."); }
            channelGate.Dispose();
        }
    }

    private async Task ReadQueueToChannelAsync(string queue, Guid tenantId, string? workerIdentity, ChannelWriter<ScanJobDelivery> writer, CancellationToken cancellationToken)
    {
        await foreach (var delivery in ReadQueueAsync(queue, tenantId, workerIdentity, cancellationToken)) await writer.WriteAsync(delivery, cancellationToken);
    }

    private async ValueTask AcknowledgeAsync(IChannel channel, SemaphoreSlim gate, ulong deliveryTag, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try { await channel.BasicAckAsync(deliveryTag, false, cancellationToken); }
        finally { gate.Release(); }
    }

    private async ValueTask RejectAsync(IChannel channel, SemaphoreSlim gate, ulong deliveryTag, ScanJobMessage message, int attempt, bool retry, CancellationToken cancellationToken)
    {
        if (retry && attempt < MaxAttempts)
            await PublishAsync(RetryQueueFor(message.TenantId), message with { Attempt = attempt + 1 }, attempt + 1, cancellationToken);
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (retry && attempt < MaxAttempts) await channel.BasicAckAsync(deliveryTag, false, cancellationToken);
            else await channel.BasicNackAsync(deliveryTag, false, false, cancellationToken);
        }
        finally { gate.Release(); }
    }

    private async ValueTask PublishAsync(string queue, ScanJobMessage message, int attempt, CancellationToken cancellationToken)
    {
        using var activity = ActivitySource.StartActivity("rabbitmq.publish");
        activity?.SetTag("messaging.destination.name", queue);
        var connection = await provider.GetConnectionAsync(cancellationToken);
        var options = new CreateChannelOptions(true, true);
        await using var channel = await connection.CreateChannelAsync(options, cancellationToken);
        await DeclareTopologyAsync(channel, queue, cancellationToken);
        var properties = new BasicProperties { Persistent = true, ContentType = "application/json", MessageId = message.JobId.ToString(), Headers = new Dictionary<string, object?> { ["x-attempt"] = attempt, ["x-tenant-id"] = message.TenantId.ToString() } };
        await channel.BasicPublishAsync(Exchange, queue, true, properties, JsonSerializer.SerializeToUtf8Bytes(message), cancellationToken);
    }

    private async Task DeclareTopologyAsync(IChannel channel, string requestedQueue, CancellationToken cancellationToken)
    {
        await channel.ExchangeDeclareAsync(DeadExchange, ExchangeType.Direct, true, false, cancellationToken: cancellationToken);
        var tenantSuffix = requestedQueue.Contains('.', StringComparison.Ordinal) ? requestedQueue[(requestedQueue.LastIndexOf('.') + 1)..] : string.Empty;
        var deadQueue = string.IsNullOrWhiteSpace(tenantSuffix) ? DeadQueue : $"{DeadQueue}.{tenantSuffix}";
        await channel.QueueDeclareAsync(deadQueue, true, false, false, cancellationToken: cancellationToken);
        await channel.QueueBindAsync(deadQueue, DeadExchange, deadQueue, cancellationToken: cancellationToken);
        if (requestedQueue.StartsWith(RetryQueue, StringComparison.Ordinal))
        {
            var mainQueue = requestedQueue[RetryQueue.Length..] is var suffix && !string.IsNullOrEmpty(suffix) ? MainQueue + suffix : MainQueue;
            var retryArguments = new Dictionary<string, object?> { ["x-message-ttl"] = RetryDelayMs, ["x-dead-letter-exchange"] = Exchange, ["x-dead-letter-routing-key"] = mainQueue };
            await channel.QueueDeclareAsync(requestedQueue, true, false, false, retryArguments, cancellationToken: cancellationToken);
        }
        else if (requestedQueue.StartsWith(MainQueue, StringComparison.Ordinal))
        {
            var mainArguments = new Dictionary<string, object?> { ["x-dead-letter-exchange"] = DeadExchange, ["x-dead-letter-routing-key"] = deadQueue };
            await channel.QueueDeclareAsync(requestedQueue, true, false, false, mainArguments, cancellationToken: cancellationToken);
        }
        else await channel.QueueDeclareAsync(requestedQueue, true, false, false, cancellationToken: cancellationToken);
    }

    private static string MainQueueFor(Guid tenantId) => tenantId == Guid.Empty ? MainQueue : $"{MainQueue}.{tenantId:N}";
    private static string MainQueueForWorker(Guid tenantId, string workerIdentity)
        => $"{MainQueue}.{tenantId:N}.worker.{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(workerIdentity.Trim()))).ToLowerInvariant()}";
    private static string RetryQueueFor(Guid tenantId) => tenantId == Guid.Empty ? RetryQueue : $"{RetryQueue}.{tenantId:N}";
    private static string CancellationQueueFor(Guid tenantId, string workerIdentity)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(workerIdentity))).ToLowerInvariant();
        return $"{CancellationQueue}.{tenantId:N}.{hash}";
    }
    private static ScanJobMessage ParseMessage(ReadOnlySpan<byte> body)
    {
        try
        {
            var message = JsonSerializer.Deserialize<ScanJobMessage>(body);
            if (message is not null && message.JobId != Guid.Empty) return message;
        }
        catch { }
        var id = JsonSerializer.Deserialize<Guid>(body);
        return new ScanJobMessage(id, Guid.Empty, null, 0);
    }
    private static int ReadAttempt(IDictionary<string, object?>? headers)
    {
        if (headers is null || !headers.TryGetValue("x-attempt", out var value)) return 0;
        return value switch { int integer => integer, long longValue => (int)longValue, byte byteValue => byteValue, byte[] bytes when int.TryParse(System.Text.Encoding.UTF8.GetString(bytes), out var parsed) => parsed, _ => 0 };
    }
}

public sealed class OutboxDispatcher(IServiceScopeFactory scopeFactory, RabbitMqScanJobQueue queue, IConfiguration configuration, ILogger<OutboxDispatcher> logger) : BackgroundService
{
    private readonly string owner = $"dispatcher-{Guid.NewGuid():N}";
    private TimeSpan LeaseDuration => TimeSpan.FromSeconds(Math.Clamp(configuration.GetValue("Messaging:OutboxLeaseSeconds", 60), 10, 3600));
    private TimeSpan RetryBaseDelay => TimeSpan.FromSeconds(Math.Clamp(configuration.GetValue("Messaging:OutboxRetryBaseSeconds", 2), 1, 300));
    private TimeSpan RetryMaxDelay => TimeSpan.FromSeconds(Math.Clamp(configuration.GetValue("Messaging:OutboxRetryMaxSeconds", 300), 10, 86_400));

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var pending = await ClaimPendingAsync(db, stoppingToken);
                foreach (var message in pending)
                {
                    try
                    {
                        await queue.PublishOutboxAsync(message, stoppingToken);
                        message.MarkDispatched();
                    }
                    catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
                    {
                        message.RecordFailure(exception.Message, DateTimeOffset.UtcNow, RetryBaseDelay, RetryMaxDelay);
                        logger.LogWarning(exception, "Outbox message {MessageId} failed on attempt {Attempt}.", message.Id, message.AttemptCount);
                    }
                    await db.SaveChangesAsync(stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
            catch (Exception exception) { logger.LogError(exception, "Outbox dispatcher cycle failed."); }
            await Task.Delay(TimeSpan.FromMilliseconds(500), stoppingToken);
        }
    }

    private async Task<List<OutboxMessage>> ClaimPendingAsync(AppDbContext db, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        List<OutboxMessage> pending;
        if (db.Database.ProviderName?.Contains("Npgsql", StringComparison.OrdinalIgnoreCase) == true)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            pending = await db.OutboxMessages.FromSqlInterpolated($"SELECT * FROM \"OutboxMessages\" WHERE \"DispatchedAt\" IS NULL AND (\"NextAttemptAt\" IS NULL OR \"NextAttemptAt\" <= {now}) AND (\"LeaseExpiresAt\" IS NULL OR \"LeaseExpiresAt\" <= {now}) ORDER BY \"CreatedAt\" LIMIT 50 FOR UPDATE SKIP LOCKED").ToListAsync(cancellationToken);
            foreach (var message in pending) message.TryAcquireLease(owner, now, LeaseDuration);
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        else
        {
            pending = await db.OutboxMessages.Where(x => x.DispatchedAt == null && (x.NextAttemptAt == null || x.NextAttemptAt <= now) && (x.LeaseExpiresAt == null || x.LeaseExpiresAt <= now)).OrderBy(x => x.CreatedAt).Take(50).ToListAsync(cancellationToken);
            pending = pending.Where(message => message.TryAcquireLease(owner, now, LeaseDuration)).ToList();
            await db.SaveChangesAsync(cancellationToken);
        }
        return pending;
    }
}
