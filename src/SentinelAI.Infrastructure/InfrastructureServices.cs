using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using SentinelAI.Application;
using SentinelAI.Domain;
using SentinelAI.Security.Policy;

namespace SentinelAI.Infrastructure;

public static class InfrastructureServices
{
    public static IServiceCollection AddSentinelInfrastructure(this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        services.AddDbContext<AppDbContext>(options =>
        {
            var provider = configuration["Database:Provider"] ?? (environment.IsDevelopment() ? "InMemory" : "Postgres");
            if (provider.Equals("InMemory", StringComparison.OrdinalIgnoreCase)) options.UseInMemoryDatabase("sentinelai");
            else options.UseNpgsql(configuration.GetConnectionString("SentinelAI") ?? "Host=localhost;Database=sentinelai;Username=sentinelai;Password=sentinelai");
        });
        services.AddScoped<IAppDbContext>(sp => sp.GetRequiredService<AppDbContext>());
        services.AddSingleton<IHostAddressResolver, SystemHostAddressResolver>();
        services.AddScoped<ITargetScopeValidator, TargetScopeValidator>();
        services.AddScoped<ScanExecutionService>();
        services.AddSingleton<WorkerCancellationRegistry>();

        var messagingMode = configuration["Messaging:Mode"] ?? (environment.IsDevelopment() ? "InMemory" : "RabbitMq");
        if (messagingMode.Equals("RabbitMq", StringComparison.OrdinalIgnoreCase))
        {
            services.AddSingleton<RabbitMqConnectionProvider>();
            services.AddSingleton<IScanJobQueue, RabbitMqScanJobQueue>();
        }
        else
        {
            services.AddSingleton<IScanJobQueue, InMemoryScanJobQueue>();
            if (configuration.GetValue("Worker:RunInProcess", false)) services.AddHostedService<ScanJobProcessor>();
        }
        return services;
    }
}

public sealed class InMemoryScanJobQueue : IScanJobQueue
{
    private readonly Channel<Guid> jobs = Channel.CreateUnbounded<Guid>();
    private readonly Channel<Guid> cancellations = Channel.CreateUnbounded<Guid>();
    public ValueTask EnqueueAsync(Guid jobId, CancellationToken cancellationToken = default) => jobs.Writer.WriteAsync(jobId, cancellationToken);
    public async IAsyncEnumerable<ScanJobDelivery> ReadAllAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await foreach (var jobId in jobs.Reader.ReadAllAsync(cancellationToken))
            yield return new ScanJobDelivery(jobId, 0, static _ => ValueTask.CompletedTask, static (_, _) => ValueTask.CompletedTask);
    }
    public ValueTask RequestCancellationAsync(Guid jobId, CancellationToken cancellationToken = default) => cancellations.Writer.WriteAsync(jobId, cancellationToken);
    public IAsyncEnumerable<Guid> ReadCancellationsAsync(CancellationToken cancellationToken = default) => cancellations.Reader.ReadAllAsync(cancellationToken);
}

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

public sealed class ScanExecutionService(AppDbContext db, ITargetScopeValidator validator, IConfiguration configuration, ILogger<ScanExecutionService> logger)
{
    private static readonly ActivitySource ActivitySource = new("SentinelAI.Worker");
    private readonly int executionDelayMs = Math.Clamp(configuration.GetValue("Worker:ExecutionDelayMs", 50), 0, 60_000);

    public async Task RecoverInterruptedJobsAsync(CancellationToken cancellationToken, Guid? authorizedTenantId = null)
    {
        var query = db.AgentJobs.Where(x => x.Status == ScanJobStatus.Running);
        if (authorizedTenantId is not null) query = query.Where(x => x.TenantId == authorizedTenantId.Value);
        var jobs = await query.ToListAsync(cancellationToken);
        foreach (var job in jobs)
        {
            job.RecoverInterrupted();
            var execution = await db.AgentExecutions.SingleOrDefaultAsync(x => x.AgentJobId == job.Id, cancellationToken);
            if (execution?.Status == AgentExecutionStatus.Running) execution.Cancel();
        }
        if (jobs.Count > 0) await db.SaveChangesAsync(cancellationToken);
    }

    public async Task ExecuteAsync(Guid jobId, CancellationToken cancellationToken, Guid? authorizedTenantId = null)
    {
        using var activity = ActivitySource.StartActivity("sentinelai.job.execute");
        activity?.SetTag("sentinelai.job.id", jobId);
        var job = await db.AgentJobs.SingleOrDefaultAsync(x => x.Id == jobId && (authorizedTenantId == null || x.TenantId == authorizedTenantId.Value), cancellationToken);
        if (job is null || job.Status is ScanJobStatus.Completed or ScanJobStatus.Failed or ScanJobStatus.Cancelled or ScanJobStatus.Expired) return;
        if (job.ExpiresAt <= DateTimeOffset.UtcNow) { job.Expire(); await db.SaveChangesAsync(cancellationToken); return; }
        if (!job.TryStart()) return;

        var execution = await db.AgentExecutions.SingleAsync(x => x.AgentJobId == job.Id, cancellationToken);
        execution.Start();
        var scopeDefinition = await db.TargetScopes.SingleAsync(x => x.Id == job.ScopeId && x.TenantId == job.TenantId, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(scopeDefinition.MaxExecutionSeconds));
        try
        {
            foreach (var target in scopeDefinition.Targets)
            {
                timeout.Token.ThrowIfCancellationRequested();
                var validation = await validator.ValidateExecutionAsync(scopeDefinition, job.TenantId, target.Kind, target.Value, job.OperationProfile, timeout.Token);
                if (!validation.IsValid) throw new ScopeValidationException(validation.Errors);
                if (executionDelayMs > 0) await Task.Delay(executionDelayMs, timeout.Token);
                var asset = await db.Assets.SingleOrDefaultAsync(x => x.TenantId == job.TenantId && x.ScopeId == scopeDefinition.Id && x.Address == target.Value, timeout.Token);
                if (asset is null) { asset = new Asset(job.TenantId, scopeDefinition.Id, target.Value, target.Kind); db.Assets.Add(asset); }
                asset.MarkSeen(false);
            }

            await db.Entry(job).ReloadAsync(timeout.Token);
            if (job.Status == ScanJobStatus.Cancelled) { execution.Cancel(); await db.SaveChangesAsync(timeout.Token); return; }
            if (job.ExpiresAt <= DateTimeOffset.UtcNow) { job.Expire(); execution.Cancel(); await db.SaveChangesAsync(timeout.Token); return; }
            execution.Complete(); job.Complete();
            db.AuditEvents.Add(new AuditEvent(job.TenantId, job.RequestedBy, "scan.completed", nameof(AgentJob), job.Id, "Passive assessment completed; no active network probing was performed."));
            await db.SaveChangesAsync(timeout.Token);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            await db.Entry(job).ReloadAsync(CancellationToken.None);
            if (job.Status is ScanJobStatus.Queued or ScanJobStatus.Running)
            {
                job.Expire();
                execution.Cancel();
                db.AuditEvents.Add(new AuditEvent(job.TenantId, job.RequestedBy, "scan.expired", nameof(AgentJob), job.Id, "Execution duration or worker cancellation limit was reached."));
                await db.SaveChangesAsync(CancellationToken.None);
            }
            else if (job.Status == ScanJobStatus.Cancelled)
            {
                execution.Cancel();
                await db.SaveChangesAsync(CancellationToken.None);
            }
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Job {JobId} failed during execution.", jobId);
            throw;
        }
    }

    public async Task RequeueOrFailAsync(Guid jobId, int attempt, int maxAttempts, string reason, CancellationToken cancellationToken)
    {
        var job = await db.AgentJobs.SingleOrDefaultAsync(x => x.Id == jobId, cancellationToken);
        if (job is null) return;
        var execution = await db.AgentExecutions.SingleOrDefaultAsync(x => x.AgentJobId == job.Id, cancellationToken);
        if (attempt >= maxAttempts)
        {
            execution?.Fail(reason); job.Fail(reason);
        }
        else
        {
            job.RecoverInterrupted();
            if (execution?.Status == AgentExecutionStatus.Running) execution.Cancel();
        }
        await db.SaveChangesAsync(cancellationToken);
    }
}

public sealed class ScanJobProcessor(IServiceScopeFactory scopeFactory, IScanJobQueue queue, WorkerCancellationRegistry cancellations, ILogger<ScanJobProcessor> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var job in queue.ReadAllAsync(stoppingToken))
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            var cancellationTask = Task.Run(async () => { await foreach (var id in queue.ReadCancellationsAsync(linked.Token)) if (id == job.JobId) linked.Cancel(); }, linked.Token);
            try
            {
                cancellations.Register(job.JobId, linked.Token);
                await using var scope = scopeFactory.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<ScanExecutionService>().ExecuteAsync(job.JobId, linked.Token);
                await job.AcknowledgeAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
            catch (Exception exception) { logger.LogError(exception, "In-process job {JobId} failed.", job.JobId); await job.RejectAsync(true, stoppingToken); }
            finally { cancellations.Remove(job.JobId); linked.Cancel(); try { await cancellationTask; } catch (OperationCanceledException) { } }
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

    public async ValueTask EnqueueAsync(Guid jobId, CancellationToken cancellationToken = default)
        => await PublishAsync(MainQueue, jobId, 0, cancellationToken);

    public async ValueTask RequestCancellationAsync(Guid jobId, CancellationToken cancellationToken = default)
        => await PublishAsync(CancellationQueue, jobId, 0, cancellationToken);

    public async IAsyncEnumerable<ScanJobDelivery> ReadAllAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await foreach (var delivery in ReadQueueAsync(MainQueue, cancellationToken)) yield return delivery;
    }

    public async IAsyncEnumerable<Guid> ReadCancellationsAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await foreach (var delivery in ReadQueueAsync(CancellationQueue, cancellationToken))
        {
            await delivery.AcknowledgeAsync(cancellationToken);
            yield return delivery.JobId;
        }
    }

    private async IAsyncEnumerable<ScanJobDelivery> ReadQueueAsync(string queue, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var connection = await provider.GetConnectionAsync(cancellationToken);
        await using var channel = await connection.CreateChannelAsync(cancellationToken: cancellationToken);
        await DeclareTopologyAsync(channel, cancellationToken);
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
                yield return new ScanJobDelivery(ParseJobId(args.Body.Span), attempt,
                    ct => AcknowledgeAsync(channel, channelGate, args.DeliveryTag, ct),
                    (retry, ct) => RejectAsync(channel, channelGate, args.DeliveryTag, ParseJobId(args.Body.Span), attempt, retry, ct));
            }
        }
        finally
        {
            deliveries.Writer.TryComplete();
            try { await channel.BasicCancelAsync(consumerTag, cancellationToken: CancellationToken.None); } catch (Exception exception) { logger.LogDebug(exception, "RabbitMQ consumer cancellation failed during shutdown."); }
            channelGate.Dispose();
        }
    }

    private async ValueTask AcknowledgeAsync(IChannel channel, SemaphoreSlim gate, ulong deliveryTag, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try { await channel.BasicAckAsync(deliveryTag, false, cancellationToken); }
        finally { gate.Release(); }
    }

    private async ValueTask RejectAsync(IChannel channel, SemaphoreSlim gate, ulong deliveryTag, Guid jobId, int attempt, bool retry, CancellationToken cancellationToken)
    {
        if (retry && attempt < MaxAttempts) await PublishAsync(RetryQueue, jobId, attempt + 1, cancellationToken);
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (retry && attempt < MaxAttempts) await channel.BasicAckAsync(deliveryTag, false, cancellationToken);
            else await channel.BasicNackAsync(deliveryTag, false, false, cancellationToken);
        }
        finally { gate.Release(); }
    }

    private async ValueTask PublishAsync(string queue, Guid jobId, int attempt, CancellationToken cancellationToken)
    {
        using var activity = ActivitySource.StartActivity("rabbitmq.publish");
        activity?.SetTag("messaging.destination.name", queue);
        var connection = await provider.GetConnectionAsync(cancellationToken);
        await using var channel = await connection.CreateChannelAsync(cancellationToken: cancellationToken);
        await DeclareTopologyAsync(channel, cancellationToken);
        var properties = new BasicProperties { Persistent = true, ContentType = "application/json", MessageId = jobId.ToString(), Headers = new Dictionary<string, object?> { ["x-attempt"] = attempt } };
        await channel.BasicPublishAsync(Exchange, queue, true, properties, JsonSerializer.SerializeToUtf8Bytes(jobId), cancellationToken);
    }

    private async Task DeclareTopologyAsync(IChannel channel, CancellationToken cancellationToken)
    {
        await channel.ExchangeDeclareAsync(DeadExchange, ExchangeType.Direct, true, false, cancellationToken: cancellationToken);
        await channel.QueueDeclareAsync(DeadQueue, true, false, false, cancellationToken: cancellationToken);
        await channel.QueueBindAsync(DeadQueue, DeadExchange, DeadQueue, cancellationToken: cancellationToken);
        var mainArguments = new Dictionary<string, object?> { ["x-dead-letter-exchange"] = DeadExchange, ["x-dead-letter-routing-key"] = DeadQueue };
        await channel.QueueDeclareAsync(MainQueue, true, false, false, mainArguments, cancellationToken: cancellationToken);
        var retryArguments = new Dictionary<string, object?> { ["x-message-ttl"] = RetryDelayMs, ["x-dead-letter-exchange"] = Exchange, ["x-dead-letter-routing-key"] = MainQueue };
        await channel.QueueDeclareAsync(RetryQueue, true, false, false, retryArguments, cancellationToken: cancellationToken);
        await channel.QueueDeclareAsync(CancellationQueue, true, false, false, cancellationToken: cancellationToken);
    }

    private static Guid ParseJobId(ReadOnlySpan<byte> body) => JsonSerializer.Deserialize<Guid>(body) is var id && id != Guid.Empty ? id : throw new InvalidOperationException("RabbitMQ message did not contain a valid job id.");
    private static int ReadAttempt(IDictionary<string, object?>? headers)
    {
        if (headers is null || !headers.TryGetValue("x-attempt", out var value)) return 0;
        return value switch { int integer => integer, long longValue => (int)longValue, byte byteValue => byteValue, byte[] bytes when int.TryParse(System.Text.Encoding.UTF8.GetString(bytes), out var parsed) => parsed, _ => 0 };
    }
}
