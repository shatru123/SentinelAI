using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.AI.Abstractions;
using SentinelAI.AI.Anthropic;
using SentinelAI.AI.Ollama;
using SentinelAI.AI.OpenAI;

namespace SentinelAI.Api;

public static class AIProviderServiceCollectionExtensions
{
    public static IServiceCollection AddSentinelAIProviders(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHttpClient("sentinelai-ai-openai", client => client.Timeout = Timeout.InfiniteTimeSpan);
        services.AddHttpClient("sentinelai-ai-anthropic", client => client.Timeout = Timeout.InfiniteTimeSpan);
        services.AddHttpClient("sentinelai-ai-ollama", client => client.Timeout = Timeout.InfiniteTimeSpan);

        services.AddSingleton<IAIProvider>(serviceProvider =>
            new OpenAIProvider(
                serviceProvider.GetRequiredService<IHttpClientFactory>().CreateClient("sentinelai-ai-openai"),
                ReadOptions(configuration, "OpenAI", "openai")));

        services.AddSingleton<IAIProvider>(serviceProvider =>
            new AnthropicProvider(
                serviceProvider.GetRequiredService<IHttpClientFactory>().CreateClient("sentinelai-ai-anthropic"),
                ReadOptions(configuration, "Anthropic", "anthropic")));

        services.AddSingleton<IAIProvider>(serviceProvider =>
            new OllamaProvider(
                serviceProvider.GetRequiredService<IHttpClientFactory>().CreateClient("sentinelai-ai-ollama"),
                ReadOptions(configuration, "Ollama", "ollama",
                    new Uri("http://127.0.0.1:11434/", UriKind.Absolute))));

        services.AddSingleton<IAIProviderFactory, AIProviderFactory>();
        return services;
    }

    private static AIProviderOptions ReadOptions(
        IConfiguration configuration,
        string sectionName,
        string providerName,
        Uri? defaultEndpoint = null)
    {
        var section = configuration.GetSection($"AI:Providers:{sectionName}");
        var legacySection = configuration.GetSection($"AI:{sectionName}");
        Uri? endpoint = defaultEndpoint;

        var configuredEndpoint = section["Endpoint"] ?? legacySection["Endpoint"];
        if (providerName == "ollama")
            configuredEndpoint ??= configuration["OLLAMA_BASE_URL"];

        if (!string.IsNullOrWhiteSpace(configuredEndpoint))
        {
            if (!Uri.TryCreate(configuredEndpoint, UriKind.Absolute, out endpoint))
                throw new InvalidOperationException($"AI:Providers:{sectionName}:Endpoint must be an absolute URI.");
        }

        var environmentApiKeyName = providerName switch
        {
            "openai" => "OPENAI_API_KEY",
            "anthropic" => "ANTHROPIC_API_KEY",
            _ => null
        };
        var environmentModelName = providerName switch
        {
            "openai" => "OPENAI_MODEL",
            "anthropic" => "ANTHROPIC_MODEL",
            "ollama" => "OLLAMA_MODEL",
            _ => null
        };

        var apiKey = section["ApiKey"] ?? legacySection["ApiKey"];
        if (apiKey is null && environmentApiKeyName is not null)
            apiKey = configuration[environmentApiKeyName];

        var model = section["Model"] ?? legacySection["Model"];
        if (model is null && environmentModelName is not null)
            model = configuration[environmentModelName];

        return new AIProviderOptions(
            providerName,
            model ?? string.Empty,
            endpoint,
            apiKey,
            section.GetValue("TimeoutSeconds", legacySection.GetValue("TimeoutSeconds", 60)),
            section.GetValue("MaxResponseBytes", legacySection.GetValue("MaxResponseBytes", 1_048_576)),
            section.GetValue("DefaultMaxOutputTokens", legacySection.GetValue("DefaultMaxOutputTokens", 2_048)),
            section["ApiVersion"] ?? legacySection["ApiVersion"] ?? "2023-06-01");
    }
}
