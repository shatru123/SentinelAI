using System.Text.Json;
using SentinelAI.AI.Abstractions;

namespace SentinelAI.AI.Anthropic;

public sealed class AnthropicProvider(HttpClient httpClient, AIProviderOptions options) : IAIProvider
{
    private const string DefaultEndpoint = "https://api.anthropic.com/";

    public string Name => "anthropic";
    public bool IsConfigured => !string.IsNullOrWhiteSpace(options.ApiKey) && !string.IsNullOrWhiteSpace(options.Model);

    public async Task<AIResponse> AnalyzeAsync(AIRequest request, CancellationToken cancellationToken = default)
    {
        if (!IsConfigured) throw new AIProviderUnavailableException("Anthropic requires AI:Providers:Anthropic:ApiKey and Model configuration.");

        var model = AIProviderHttpSupport.ResolveModel(request, options);
        var maxTokens = AIProviderHttpSupport.ResolveMaxOutputTokens(request, options);
        var schema = AIProviderHttpSupport.ParseJsonSchema(request);
        var payload = new Dictionary<string, object?>
        {
            ["model"] = model,
            ["max_tokens"] = maxTokens,
            ["messages"] = new[] { new { role = "user", content = request.UserPrompt } }
        };
        if (!string.IsNullOrWhiteSpace(request.SystemPrompt)) payload["system"] = request.SystemPrompt;
        if (schema is not null)
        {
            payload["output_config"] = new
            {
                format = new
                {
                    type = "json_schema",
                    schema = schema.Value
                }
            };
        }

        using var message = AIProviderHttpSupport.CreateJsonRequest(
            HttpMethod.Post,
            AIProviderHttpSupport.CreateEndpoint(options, DefaultEndpoint, "v1/messages"),
            payload);
        message.Headers.TryAddWithoutValidation("x-api-key", options.ApiKey);
        message.Headers.TryAddWithoutValidation("anthropic-version", options.ApiVersion);

        try
        {
            return await AIProviderHttpSupport.SendAsync(
                httpClient, message, options, cancellationToken,
                async (response, token) =>
                {
                    var body = await AIProviderHttpSupport.ReadBodyAsync(response, options, token);
                    using var document = JsonDocument.Parse(body);
                    var root = document.RootElement;
                    var content = ExtractText(root);
                    if (string.IsNullOrWhiteSpace(content))
                        throw new AIProviderUnavailableException("Anthropic returned no text content.");

                    AIProviderHttpSupport.ValidateStructuredResponse(content, schema is not null, Name);
                    var usage = root.TryGetProperty("usage", out var usageElement) ? usageElement : default;
                    return new AIResponse(
                        Name,
                        GetString(root, "model") ?? model,
                        content,
                        GetInt(usage, "input_tokens"),
                        GetInt(usage, "output_tokens"),
                        GetString(root, "id"),
                        GetString(root, "stop_reason"),
                        schema is not null);
                });
        }
        catch (JsonException exception)
        {
            throw new AIProviderUnavailableException("Anthropic returned an invalid response document.", exception);
        }
    }

    public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
    {
        if (!IsConfigured) return false;

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            AIProviderHttpSupport.CreateEndpoint(options, DefaultEndpoint, "v1/models?limit=1"));
        request.Headers.TryAddWithoutValidation("x-api-key", options.ApiKey);
        request.Headers.TryAddWithoutValidation("anthropic-version", options.ApiVersion);
        try
        {
            return await AIProviderHttpSupport.SendAsync(
                httpClient, request, options, cancellationToken,
                (_, _) => Task.FromResult(true),
                timeoutSeconds: Math.Min(options.TimeoutSeconds, 5));
        }
        catch (AIProviderUnavailableException)
        {
            return false;
        }
    }

    private static string? ExtractText(JsonElement root)
    {
        if (!root.TryGetProperty("content", out var blocks) || blocks.ValueKind != JsonValueKind.Array) return null;
        return string.Join(Environment.NewLine, blocks.EnumerateArray()
            .Where(block => GetString(block, "type") == "text")
            .Select(block => GetString(block, "text"))
            .Where(text => !string.IsNullOrWhiteSpace(text)));
    }

    private static string? GetString(JsonElement element, string property)
        => element.ValueKind == JsonValueKind.Object &&
           element.TryGetProperty(property, out var value) &&
           value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static int? GetInt(JsonElement element, string property)
        => element.ValueKind == JsonValueKind.Object &&
           element.TryGetProperty(property, out var value) &&
           value.TryGetInt32(out var result)
            ? result
            : null;
}
