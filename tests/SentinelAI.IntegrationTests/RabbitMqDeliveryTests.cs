using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Infrastructure;

namespace SentinelAI.IntegrationTests;

public sealed class RabbitMqDeliveryTests
{
    [Fact]
    public async Task RabbitMq_delivery_is_manual_and_retryable()
    {
        var configuration = new ConfigurationManager();
        configuration["RabbitMQ:Host"] = Environment.GetEnvironmentVariable("RABBITMQ_TEST_HOST") ?? "localhost";
        configuration["RabbitMQ:Port"] = Environment.GetEnvironmentVariable("RABBITMQ_TEST_PORT") ?? "5672";
        configuration["RabbitMQ:Username"] = Environment.GetEnvironmentVariable("RABBITMQ_TEST_USER") ?? "sentinelai";
        configuration["RabbitMQ:Password"] = Environment.GetEnvironmentVariable("RABBITMQ_TEST_PASSWORD") ?? "replace-with-local-dev-password";
        configuration["RabbitMQ:RetryDelayMs"] = "100";
        configuration["RabbitMQ:MaxAttempts"] = "3";
        await using var provider = new RabbitMqConnectionProvider(configuration, NullLogger<RabbitMqConnectionProvider>.Instance);
        var queue = new RabbitMqScanJobQueue(provider, configuration, NullLogger<RabbitMqScanJobQueue>.Instance);
        var jobId = Guid.NewGuid();
        await queue.EnqueueAsync(jobId);

        await using var firstReader = queue.ReadAllAsync().GetAsyncEnumerator();
        Assert.True(await firstReader.MoveNextAsync());
        Assert.Equal(jobId, firstReader.Current.JobId);
        await firstReader.Current.RejectAsync(true, CancellationToken.None);
        await firstReader.DisposeAsync();
        await Task.Delay(350);

        await using var retryReader = queue.ReadAllAsync().GetAsyncEnumerator();
        Assert.True(await retryReader.MoveNextAsync());
        Assert.Equal(jobId, retryReader.Current.JobId);
        Assert.Equal(1, retryReader.Current.Attempt);
        await retryReader.Current.AcknowledgeAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Cancellation_is_routed_by_tenant_and_exact_worker_identity()
    {
        var configuration = new ConfigurationManager();
        configuration["RabbitMQ:Host"] = Environment.GetEnvironmentVariable("RABBITMQ_TEST_HOST") ?? "localhost";
        configuration["RabbitMQ:Port"] = Environment.GetEnvironmentVariable("RABBITMQ_TEST_PORT") ?? "5672";
        configuration["RabbitMQ:Username"] = Environment.GetEnvironmentVariable("RABBITMQ_TEST_USER") ?? "sentinelai";
        configuration["RabbitMQ:Password"] = Environment.GetEnvironmentVariable("RABBITMQ_TEST_PASSWORD") ?? "replace-with-local-dev-password";
        await using var provider = new RabbitMqConnectionProvider(configuration, NullLogger<RabbitMqConnectionProvider>.Instance);
        var queue = new RabbitMqScanJobQueue(provider, configuration, NullLogger<RabbitMqScanJobQueue>.Instance);
        var workerIdentity = "same-worker/tenant-bound";
        var tenantA = Guid.NewGuid();
        var tenantB = Guid.NewGuid();
        var jobA = Guid.NewGuid();
        var jobB = Guid.NewGuid();
        await queue.RequestCancellationAsync(jobA, tenantA, workerIdentity, CancellationToken.None);
        await queue.RequestCancellationAsync(jobB, tenantB, workerIdentity, CancellationToken.None);

        await using var readerA = queue.ReadCancellationsAsync(tenantA, workerIdentity).GetAsyncEnumerator();
        Assert.True(await readerA.MoveNextAsync());
        Assert.Equal(jobA, readerA.Current);

        await using var readerB = queue.ReadCancellationsAsync(tenantB, workerIdentity).GetAsyncEnumerator();
        Assert.True(await readerB.MoveNextAsync());
        Assert.Equal(jobB, readerB.Current);
    }
}
