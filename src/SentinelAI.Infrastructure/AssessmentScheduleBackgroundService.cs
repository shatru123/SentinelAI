using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SentinelAI.Application;

namespace SentinelAI.Infrastructure;

public sealed class AssessmentScheduleBackgroundService(
    IServiceScopeFactory scopeFactory,
    IConfiguration configuration,
    ILogger<AssessmentScheduleBackgroundService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!configuration.GetValue("Scheduling:Enabled", true))
        {
            logger.LogInformation("Scheduled reassessment dispatcher is disabled by configuration.");
            return;
        }

        var intervalSeconds = Math.Clamp(configuration.GetValue("Scheduling:PollIntervalSeconds", 30), 5, 300);
        var batchSize = Math.Clamp(configuration.GetValue("Scheduling:BatchSize", 20), 1, 100);
        logger.LogInformation("Scheduled reassessment dispatcher started with a {IntervalSeconds}s poll interval and batch size {BatchSize}.",
            intervalSeconds, batchSize);

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(intervalSeconds));
        do
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<AssessmentScheduleProcessor>()
                    .RunOnceAsync(batchSize, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "Scheduled reassessment cycle failed; persisted due occurrences remain eligible for retry.");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
