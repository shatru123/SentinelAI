using System.Text.Json;
using SentinelAI.AI.Abstractions;

namespace SentinelAI.AI.Ollama;

public sealed class OllamaProvider(HttpClient httpClient, AIProviderOptions options) : IAIProvider
{
    private const string DefaultEndpoint = "http://127.0.0.1:11434/";

    public string Name => "ollama";
    public bool IsConfigured => !string.IsNullOrWhiteSpace(options.Model);

    public async Task<AIResponse> AnalyzeAsync(AIRequest request, CancellationToken cancellationToken = default)
    {
        if (!IsConfigured) throw new AIProviderUnavailableException("Ollama requires AI:Providers:Ollama:Model configuration.");

        var model = AIProviderHttpSupport.ResolveModel(request, options);
        var maxTokens = AIProviderHttpSupport.ResolveMaxOutputTokens(request, options);
        var schema = AIProviderHttpSupport.ParseJsonSchema(request);
        var messages = new List<object>();
        if (!string.IsNullOrWhiteSpace(request.SystemPrompt))
            messages.Add(new { role = "system", content = request.SystemPrompt });
        messages.Add(new { role = "user", content = request.UserPrompt });

        var payload = new Dictionary<string, object?>
        {
            ["model"] = model,
            ["messages"] = messages,
            ["stream"] = false,
            ["options"] = new { num_predict = maxTokens }
        };
        if (schema is not null) payload["format"] = schema.Value;

        using var message = AIProviderHttpSupport.CreateJsonRequest(
            HttpMethod.Post,
            AIProviderHttpSupport.CreateEndpoint(options, DefaultEndpoint, "api/chat", allowHttpLoopback: true),
            payload);

        try
        {
            return await AIProviderHttpSupport.SendAsync(
                httpClient, message, options, cancellationToken,
                async (response, token) =>
                {
                    var body = await AIProviderHttpSupport.ReadBodyAsync(response, options, token);
                    using var document = JsonDocument.Parse(body);
                    var root = document.RootElement;
                    var done = root.TryGetProperty("done", out var doneValue) &&
                               doneValue.ValueKind == JsonValueKind.True;
                    if (!done) throw new AIProviderUnavailableException("Ollama returned an incomplete response.");
                    var content = root.TryGetProperty("message", out var messageElement) &&
                                  messageElement.TryGetProperty("content", out var contentElement) &&
                                  contentElement.ValueKind == JsonValueKind.String
                        ? contentElement.GetString() ?? string.Empty
                        : string.Empty;
                    if (string.IsNullOrWhiteSpace(content))
                        throw new AIProviderUnavailableException("Ollama returned no text content.");

                    AIProviderHttpSupport.ValidateStructuredResponse(content, schema is not null, Name);
                    return new AIResponse(
                        Name,
                        GetString(root, "model") ?? model,
                        content,
                        GetInt(root, "prompt_eval_count"),
                        GetInt(root, "eval_count"),
                        null,
                        GetString(root, "done_reason"),
                        schema is not null);
                });
        }
        catch (JsonException exception)
        {
            throw new AIProviderUnavailableException("Ollama returned an invalid response document.", exception);
        }
    }

    public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
    {
        if (!IsConfigured) return false;

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            AIProviderHttpSupport.CreateEndpoint(options, DefaultEndpoint, "api/tags", allowHttpLoopback: true));
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
