using System.Net.Http.Headers;
using System.Text.Json;
using SentinelAI.AI.Abstractions;

namespace SentinelAI.AI.OpenAI;

public sealed class OpenAIProvider(HttpClient httpClient, AIProviderOptions options) : IAIProvider
{
    private const string DefaultEndpoint = "https://api.openai.com/v1/";

    public string Name => "openai";
    public bool IsConfigured => !string.IsNullOrWhiteSpace(options.ApiKey) && !string.IsNullOrWhiteSpace(options.Model);

    public async Task<AIResponse> AnalyzeAsync(AIRequest request, CancellationToken cancellationToken = default)
    {
        if (!IsConfigured) throw new AIProviderUnavailableException("OpenAI requires AI:Providers:OpenAI:ApiKey and Model configuration.");

        var model = AIProviderHttpSupport.ResolveModel(request, options);
        var maxTokens = AIProviderHttpSupport.ResolveMaxOutputTokens(request, options);
        var schema = AIProviderHttpSupport.ParseJsonSchema(request);
        var payload = new Dictionary<string, object?>
        {
            ["model"] = model,
            ["instructions"] = request.SystemPrompt,
            ["input"] = request.UserPrompt,
            ["max_output_tokens"] = maxTokens,
            ["store"] = false
        };
        if (schema is not null)
        {
            payload["text"] = new
            {
                format = new
                {
                    type = "json_schema",
                    name = "sentinelai_analysis",
                    strict = true,
                    schema = schema.Value
                }
            };
        }

        using var message = AIProviderHttpSupport.CreateJsonRequest(
            HttpMethod.Post,
            AIProviderHttpSupport.CreateEndpoint(options, DefaultEndpoint, "responses"),
            payload);
        message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.ApiKey);

        try
        {
            return await AIProviderHttpSupport.SendAsync(
                httpClient, message, options, cancellationToken,
                async (response, token) =>
                {
                    var body = await AIProviderHttpSupport.ReadBodyAsync(response, options, token);
                    using var document = JsonDocument.Parse(body);
                    var root = document.RootElement;
                    var status = GetString(root, "status");
                    if (!string.IsNullOrWhiteSpace(status) && !status.Equals("completed", StringComparison.OrdinalIgnoreCase))
                        throw new AIProviderUnavailableException("OpenAI returned an incomplete response.");

                    var content = ExtractText(root);
                    if (string.IsNullOrWhiteSpace(content))
                        throw new AIProviderUnavailableException("OpenAI returned no text content.");

                    AIProviderHttpSupport.ValidateStructuredResponse(content, schema is not null, Name);
                    var usage = root.TryGetProperty("usage", out var usageElement) ? usageElement : default;
                    return new AIResponse(
                        Name,
                        GetString(root, "model") ?? model,
                        content,
                        GetInt(usage, "input_tokens"),
                        GetInt(usage, "output_tokens"),
                        GetString(root, "id"),
                        status,
                        schema is not null);
                });
        }
        catch (JsonException exception)
        {
            throw new AIProviderUnavailableException("OpenAI returned an invalid response document.", exception);
        }
    }

    public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
    {
        if (!IsConfigured) return false;

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            AIProviderHttpSupport.CreateEndpoint(options, DefaultEndpoint, "models"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.ApiKey);
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
        var parts = new List<string>();
        if (root.TryGetProperty("output_text", out var direct) && direct.ValueKind == JsonValueKind.String)
            parts.Add(direct.GetString() ?? string.Empty);

        if (parts.Count == 0 && root.TryGetProperty("output", out var output) && output.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in output.EnumerateArray())
            {
                if (!item.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Array) continue;
                foreach (var block in content.EnumerateArray())
                {
                    var type = GetString(block, "type");
                    if (type == "output_text" && GetString(block, "text") is { } text) parts.Add(text);
                    else if (type == "refusal" && GetString(block, "refusal") is { } refusal) parts.Add(refusal);
                }
            }
        }

        return string.Join(Environment.NewLine, parts).Trim();
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
