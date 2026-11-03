using SentinelAI.Agent.Vulnerability;

namespace SentinelAI.UnitTests;

public sealed class AssessmentRequestBudgetTests
{
    [Fact]
    public async Task Rolling_window_does_not_allow_a_boundary_burst()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var delays = new List<TimeSpan>();
        var budget = new AssessmentRequestBudget(10, 2, clock, (delay, _) =>
        {
            delays.Add(delay);
            clock.Advance(delay);
            return Task.CompletedTask;
        });

        await budget.ConsumeAsync(CancellationToken.None);
        clock.Advance(TimeSpan.FromSeconds(59));
        await budget.ConsumeAsync(CancellationToken.None);
        var third = budget.ConsumeAsync(CancellationToken.None);

        await third;
        Assert.Single(delays);
        Assert.Equal(TimeSpan.FromSeconds(1), delays[0]);
        Assert.Equal(3, budget.Consumed);
    }

    [Fact]
    public async Task Cancellation_while_waiting_does_not_consume_capacity()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var budget = new AssessmentRequestBudget(10, 1, new ManualTimeProvider(DateTimeOffset.UtcNow),
            async (_, token) =>
            {
                started.SetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
            });
        await budget.ConsumeAsync(CancellationToken.None);
        using var cancellation = new CancellationTokenSource();
        var waiting = budget.ConsumeAsync(cancellation.Token);
        await started.Task;
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        Assert.Equal(1, budget.Consumed);
        Assert.Equal(2, budget.Attempted);
    }

    [Fact]
    public async Task Lease_loss_while_waiting_stops_admission()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var checks = 0;
        var budget = new AssessmentRequestBudget(10, 1, clock, (delay, _) =>
        {
            clock.Advance(delay);
            return Task.CompletedTask;
        });
        await budget.ConsumeAsync(CancellationToken.None);

        await Assert.ThrowsAsync<WebAssessmentLeaseLostException>(() => budget.ConsumeAsync(CancellationToken.None, _ => Task.FromResult(++checks < 2)));
        Assert.Equal(1, budget.Consumed);
        Assert.Equal(2, budget.Attempted);
    }

    [Fact]
    public async Task Total_budget_is_not_reset_by_rate_window()
    {
        var budget = new AssessmentRequestBudget(2, 10_000);
        await budget.ConsumeAsync(CancellationToken.None);
        await budget.ConsumeAsync(CancellationToken.None);
        await Assert.ThrowsAsync<SentinelAI.Application.ScopeValidationException>(() => budget.ConsumeAsync(CancellationToken.None));
        Assert.Equal(2, budget.Consumed);
    }

    [Fact]
    public async Task Concurrent_consumers_cannot_exceed_the_total_budget()
    {
        var budget = new AssessmentRequestBudget(4, 4);
        var results = await Task.WhenAll(Enumerable.Range(0, 32).Select(async _ =>
        {
            try
            {
                await budget.ConsumeAsync(CancellationToken.None);
                return true;
            }
            catch (SentinelAI.Application.ScopeValidationException)
            {
                return false;
            }
        }));

        Assert.Equal(4, results.Count(result => result));
        Assert.Equal(4, budget.Consumed);
        Assert.Equal(32, budget.Attempted);
    }

    private sealed class ManualTimeProvider(DateTimeOffset initial) : TimeProvider
    {
        private long utcTicks = initial.UtcTicks;
        public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref utcTicks), TimeSpan.Zero);
        public void Advance(TimeSpan amount) => Interlocked.Add(ref utcTicks, amount.Ticks);
    }
}
