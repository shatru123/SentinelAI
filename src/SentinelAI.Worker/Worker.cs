using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace SentinelAI.Worker;

public sealed class Worker(ILogger<Worker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("SentinelAI worker started in mock-adapter mode. Active network probing is disabled.");
        while (!stoppingToken.IsCancellationRequested)
        {
            logger.LogDebug("Worker heartbeat at {UtcNow}.", DateTimeOffset.UtcNow);
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        }
    }
}
