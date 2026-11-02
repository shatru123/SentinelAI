using SentinelAI.AI.Abstractions;

namespace SentinelAI.AI.Ollama;

public sealed class OllamaProvider(HttpClient httpClient, AIProviderOptions options) : IAIProvider
{
    public string Name => "ollama";
    public async Task<AIResponse> AnalyzeAsync(AIRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        if (options.Endpoint is null) throw new AIProviderUnavailableException("Ollama endpoint is not configured.");
        await Task.Yield();
        return new AIResponse(Name, request.Model ?? options.Model, "Provider adapter is configured; live calls are disabled until the Phase 4 gateway is enabled.", null, null);
    }
    public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(options.Endpoint is not null);
}
