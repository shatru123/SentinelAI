using SentinelAI.AI.Abstractions;

namespace SentinelAI.AI.OpenAI;

public sealed class OpenAIProvider(HttpClient httpClient, AIProviderOptions options) : IAIProvider
{
    public string Name => "openai";
    public async Task<AIResponse> AnalyzeAsync(AIRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        if (string.IsNullOrWhiteSpace(options.ApiKey)) throw new AIProviderUnavailableException("OpenAI is not configured.");
        await Task.Yield();
        return new AIResponse(Name, request.Model ?? options.Model, "Provider adapter is configured; live calls are disabled until the Phase 4 gateway is enabled.", null, null);
    }
    public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(!string.IsNullOrWhiteSpace(options.ApiKey));
}
