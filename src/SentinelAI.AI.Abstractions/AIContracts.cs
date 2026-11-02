namespace SentinelAI.AI.Abstractions;

public sealed record AIProviderOptions(string Name, string Model, Uri? Endpoint, string? ApiKey);
public sealed record AIRequest(string SystemPrompt, string UserPrompt, string? Model = null);
public sealed record AIResponse(string Provider, string Model, string Content, int? InputTokens, int? OutputTokens);

public interface IAIProvider
{
    string Name { get; }
    Task<AIResponse> AnalyzeAsync(AIRequest request, CancellationToken cancellationToken = default);
    Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default);
}

public interface IAIProviderFactory
{
    IAIProvider Get(string name);
    IReadOnlyCollection<string> GetNames();
}

public interface IAgentPlanner
{
    Task<IReadOnlyCollection<string>> CreateBoundedPlanAsync(string objective, IReadOnlyCollection<string> approvedCapabilities, CancellationToken cancellationToken = default);
}

public interface IAgentAnalysisService
{
    Task<AIResponse> AnalyzeFindingsAsync(string evidence, string providerName, CancellationToken cancellationToken = default);
}

public sealed class AIProviderUnavailableException(string message) : Exception(message);
