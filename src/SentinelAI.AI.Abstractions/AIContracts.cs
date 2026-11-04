namespace SentinelAI.AI.Abstractions;

public sealed record AIProviderOptions(
    string Name,
    string Model,
    Uri? Endpoint,
    string? ApiKey,
    int TimeoutSeconds = 60,
    int MaxResponseBytes = 1_048_576,
    int DefaultMaxOutputTokens = 2_048,
    string ApiVersion = "2023-06-01");

public sealed record AIRequest(
    string SystemPrompt,
    string UserPrompt,
    string? Model = null,
    int? MaxOutputTokens = null,
    string? JsonSchemaJson = null);

public sealed record AIResponse(
    string Provider,
    string Model,
    string Content,
    int? InputTokens,
    int? OutputTokens,
    string? ResponseId = null,
    string? FinishReason = null,
    bool StructuredOutput = false);

public interface IAIProvider
{
    string Name { get; }
    bool IsConfigured { get; }
    Task<AIResponse> AnalyzeAsync(AIRequest request, CancellationToken cancellationToken = default);
    Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default);
}

public interface IAIProviderFactory
{
    IAIProvider Get(string name);
    IReadOnlyCollection<string> GetNames();
}

public sealed class AIProviderFactory : IAIProviderFactory
{
    private readonly IReadOnlyDictionary<string, IAIProvider> providers;
    private readonly IReadOnlyCollection<string> names;

    public AIProviderFactory(IEnumerable<IAIProvider> providers)
    {
        ArgumentNullException.ThrowIfNull(providers);
        var items = providers.ToArray();
        var duplicate = items.GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicate is not null)
            throw new InvalidOperationException($"AI provider '{duplicate.Key}' is registered more than once.");

        this.providers = items.ToDictionary(x => x.Name, StringComparer.OrdinalIgnoreCase);
        names = Array.AsReadOnly(items.Select(x => x.Name).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    public IAIProvider Get(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("An AI provider name is required.", nameof(name));
        return providers.TryGetValue(name.Trim(), out var provider)
            ? provider
            : throw new AIProviderUnavailableException($"AI provider '{name.Trim()}' is not registered.");
    }

    public IReadOnlyCollection<string> GetNames() => names;
}

public interface IAgentPlanner
{
    Task<IReadOnlyCollection<string>> CreateBoundedPlanAsync(string objective, IReadOnlyCollection<string> approvedCapabilities, CancellationToken cancellationToken = default);
}

public interface IAgentAnalysisService
{
    Task<AIResponse> AnalyzeFindingsAsync(string evidence, string providerName, CancellationToken cancellationToken = default);
}

public sealed class AIProviderUnavailableException : Exception
{
    public AIProviderUnavailableException(string message) : base(message) { }
    public AIProviderUnavailableException(string message, Exception innerException) : base(message, innerException) { }
}
