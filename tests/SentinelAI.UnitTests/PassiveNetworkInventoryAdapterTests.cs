using SentinelAI.Agent.Network;
using SentinelAI.Application;
using SentinelAI.Domain;
using SentinelAI.Security.Policy;
using System.Diagnostics;

namespace SentinelAI.UnitTests;

public sealed class PassiveNetworkInventoryAdapterTests
{
    [Fact]
    public async Task Records_only_authorized_declarations_without_claiming_reachability()
    {
        var scopeId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var target = new TargetDefinition(TargetKind.Network, "10.20.0.5");
        var validation = new ValidatedExecutionTarget(target.Value, [System.Net.IPAddress.Parse("10.20.0.5")], DateTimeOffset.UtcNow, scopeId, tenantId, DateTimeOffset.UtcNow.AddMinutes(5), "network-inventory-passive");
        var adapter = new PassiveNetworkInventoryAdapter();

        var result = await adapter.CollectAsync([new AuthorizedInventoryTarget(target, validation)], 100, CancellationToken.None);

        var observation = Assert.Single(result);
        Assert.Equal(target.Value, observation.Address);
        Assert.False(observation.IsOnline);
        Assert.Empty(observation.Services);
    }

    [Fact]
    public async Task Declaration_processing_does_not_apply_network_request_delays()
    {
        var targets = Enumerable.Range(1, 2).Select(index =>
        {
            var value = $"10.20.0.{index}";
            var definition = new TargetDefinition(TargetKind.Network, value);
            var validation = new ValidatedExecutionTarget(value, [System.Net.IPAddress.Parse(value)], DateTimeOffset.UtcNow, Guid.NewGuid(), Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(5), "network-inventory-passive");
            return new AuthorizedInventoryTarget(definition, validation);
        }).ToArray();
        var adapter = new PassiveNetworkInventoryAdapter();
        var stopwatch = Stopwatch.StartNew();

        var result = await adapter.CollectAsync(targets, 1, CancellationToken.None);

        stopwatch.Stop();
        Assert.Equal(2, result.Count);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(1), $"Declaration-only processing took {stopwatch.Elapsed}.");
    }

    [Fact]
    public async Task Cancellation_is_honored_before_the_next_observation()
    {
        var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var adapter = new PassiveNetworkInventoryAdapter();
        var validation = new ValidatedExecutionTarget("10.20.0.5", [System.Net.IPAddress.Parse("10.20.0.5")], DateTimeOffset.UtcNow, Guid.NewGuid(), Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(5), "network-inventory-passive");

        await Assert.ThrowsAsync<OperationCanceledException>(() => adapter.CollectAsync([new AuthorizedInventoryTarget(new TargetDefinition(TargetKind.Network, validation.OriginalHostname), validation)], 100, cancellation.Token));
    }
}
