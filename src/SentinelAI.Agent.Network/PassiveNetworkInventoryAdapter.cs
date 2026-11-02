using SentinelAI.Application;

namespace SentinelAI.Agent.Network;

/// <summary>
/// Produces inventory observations from already-authorized scope declarations.
/// It intentionally performs no DNS lookup, socket operation, port probe or command execution.
/// A future active adapter must be separately reviewed and explicitly enabled.
/// </summary>
public sealed class PassiveNetworkInventoryAdapter : IPassiveInventoryAdapter
{
    public Task<IReadOnlyCollection<InventoryObservation>> CollectAsync(
        IReadOnlyCollection<AuthorizedInventoryTarget> targets,
        int requestsPerMinute,
        CancellationToken cancellationToken = default)
    {
        if (requestsPerMinute is < 1 or > 10_000) throw new ArgumentOutOfRangeException(nameof(requestsPerMinute));

        var observations = new List<InventoryObservation>(targets.Count);
        foreach (var target in targets)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // The value is already validated by TargetScopeValidator. It is recorded as an
            // offline/passive observation because no active reachability claim is made here.
            observations.Add(new InventoryObservation(target.Definition.Value, target.Definition.Kind, false, []));
        }
        return Task.FromResult<IReadOnlyCollection<InventoryObservation>>(observations);
    }
}
