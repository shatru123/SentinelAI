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
}
