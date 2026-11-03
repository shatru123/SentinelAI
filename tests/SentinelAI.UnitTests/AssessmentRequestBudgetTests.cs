using SentinelAI.Agent.Vulnerability;

namespace SentinelAI.UnitTests;

public sealed class AssessmentRequestBudgetTests
{
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
}
