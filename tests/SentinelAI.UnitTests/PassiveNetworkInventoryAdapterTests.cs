using SentinelAI.Agent.Network;
using SentinelAI.Application;
using SentinelAI.Domain;
using SentinelAI.Security.Policy;

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
    public async Task Cancellation_is_honored_before_the_next_observation()
    {
        var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var adapter = new PassiveNetworkInventoryAdapter();
        var validation = new ValidatedExecutionTarget("10.20.0.5", [System.Net.IPAddress.Parse("10.20.0.5")], DateTimeOffset.UtcNow, Guid.NewGuid(), Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(5), "network-inventory-passive");

        await Assert.ThrowsAsync<OperationCanceledException>(() => adapter.CollectAsync([new AuthorizedInventoryTarget(new TargetDefinition(TargetKind.Network, validation.OriginalHostname), validation)], 100, cancellation.Token));
    }
}
