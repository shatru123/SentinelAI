using System.Collections.Concurrent;
using SentinelAI.Application;

namespace SentinelAI.Agent.Network;

/// <summary>
/// Produces inventory observations from already-authorized scope declarations.
/// It intentionally performs no DNS lookup, socket operation, port probe or command execution.
/// A future active adapter must be separately reviewed and explicitly enabled.
/// </summary>
public sealed class PassiveNetworkInventoryAdapter : IPassiveInventoryAdapter
{
    private readonly ConcurrentDictionary<int, Window> windows = new();

    public async Task<IReadOnlyCollection<InventoryObservation>> CollectAsync(
        IReadOnlyCollection<AuthorizedInventoryTarget> targets,
        int requestsPerMinute,
        CancellationToken cancellationToken = default)
    {
        if (requestsPerMinute is < 1 or > 10_000) throw new ArgumentOutOfRangeException(nameof(requestsPerMinute));

        var observations = new List<InventoryObservation>(targets.Count);
        foreach (var target in targets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await WaitForRateLimitAsync(requestsPerMinute, cancellationToken);

            // The value is already validated by TargetScopeValidator. It is recorded as an
            // offline/passive observation because no active reachability claim is made here.
            observations.Add(new InventoryObservation(target.Definition.Value, target.Definition.Kind, false, []));
        }
        return observations;
    }

    private async Task WaitForRateLimitAsync(int requestsPerMinute, CancellationToken cancellationToken)
    {
        var window = windows.GetOrAdd(requestsPerMinute, _ => new Window());
        while (true)
        {
            TimeSpan delay;
            lock (window.SyncRoot)
            {
                var now = DateTimeOffset.UtcNow;
                while (window.Requests.Count > 0 && window.Requests.Peek() <= now.AddMinutes(-1)) window.Requests.Dequeue();
                if (window.Requests.Count < requestsPerMinute)
                {
                    window.Requests.Enqueue(now);
                    return;
                }
                delay = window.Requests.Peek().AddMinutes(1) - now;
            }
            await Task.Delay(delay, cancellationToken);
        }
    }

    private sealed class Window
    {
        public object SyncRoot { get; } = new();
        public Queue<DateTimeOffset> Requests { get; } = new();
    }
}
