using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
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
            if (provider.Equals("InMemory", StringComparison.OrdinalIgnoreCase))
                options.UseInMemoryDatabase("sentinelai");
            else
                options.UseNpgsql(configuration.GetConnectionString("SentinelAI") ?? "Host=localhost;Database=sentinelai;Username=sentinelai;Password=sentinelai");
        });
        services.AddScoped<IAppDbContext>(sp => sp.GetRequiredService<AppDbContext>());
        services.AddSingleton<IScanJobQueue, InMemoryScanJobQueue>();
        services.AddSingleton<IHostAddressResolver, SystemHostAddressResolver>();
        services.AddScoped<ITargetScopeValidator, TargetScopeValidator>();
        services.AddHostedService<ScanJobProcessor>();
        return services;
    }
}

public sealed class InMemoryScanJobQueue : IScanJobQueue
{
    private readonly Channel<Guid> channel = Channel.CreateUnbounded<Guid>(new UnboundedChannelOptions { SingleReader = false, SingleWriter = false });
    public ValueTask EnqueueAsync(Guid jobId, CancellationToken cancellationToken = default) => channel.Writer.WriteAsync(jobId, cancellationToken);
    public IAsyncEnumerable<Guid> ReadAllAsync(CancellationToken cancellationToken = default) => channel.Reader.ReadAllAsync(cancellationToken);
}

public sealed class ScanJobProcessor(IServiceScopeFactory scopeFactory, IScanJobQueue queue, ILogger<ScanJobProcessor> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var jobId in queue.ReadAllAsync(stoppingToken))
        {
            try { await ProcessAsync(jobId, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
            catch (Exception exception) { logger.LogError(exception, "Mock scan job {JobId} failed.", jobId); }
        }
    }

    private async Task ProcessAsync(Guid jobId, CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var job = await db.AgentJobs.SingleOrDefaultAsync(x => x.Id == jobId, cancellationToken);
        if (job is null || job.Status != ScanJobStatus.Queued) return;
        if (job.ExpiresAt <= DateTimeOffset.UtcNow) { job.Expire(); await db.SaveChangesAsync(cancellationToken); return; }
        job.Start();
        var execution = await db.AgentExecutions.SingleAsync(x => x.AgentJobId == job.Id, cancellationToken);
        execution.Start();
        await db.SaveChangesAsync(cancellationToken);

        var scopeDefinition = await db.TargetScopes.SingleAsync(x => x.Id == job.ScopeId && x.TenantId == job.TenantId, cancellationToken);
        foreach (var target in scopeDefinition.Targets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var asset = await db.Assets.SingleOrDefaultAsync(x => x.TenantId == job.TenantId && x.ScopeId == scopeDefinition.Id && x.Address == target.Value, cancellationToken);
            if (asset is null) { asset = new Asset(job.TenantId, scopeDefinition.Id, target.Value, target.Kind); db.Assets.Add(asset); }
            asset.MarkSeen(false);
        }
        execution.Complete(); job.Complete();
        db.AuditEvents.Add(new AuditEvent(job.TenantId, job.RequestedBy, "scan.completed", nameof(AgentJob), job.Id, "Mock assessment completed; no active network probing was performed."));
        await db.SaveChangesAsync(cancellationToken);
    }
}
