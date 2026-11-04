using System.Net;
using System.Text;
using System.Text.Json;

namespace SentinelAI.AI.Abstractions;

/// <summary>
/// Shared transport safeguards for provider adapters. Error messages intentionally omit upstream
/// response bodies so provider diagnostics cannot echo prompts, credentials, or model output.
/// </summary>
public static class AIProviderHttpSupport
{
    private const int MaximumPromptCharacters = 100_000;
    private const int MaximumJsonSchemaCharacters = 65_536;
    private const int MaximumAllowedResponseBytes = 10 * 1024 * 1024;

    public static string ResolveModel(AIRequest request, AIProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(options);
        ValidateRequest(request);
        var model = string.IsNullOrWhiteSpace(request.Model) ? options.Model : request.Model;
        if (string.IsNullOrWhiteSpace(model))
            throw new AIProviderUnavailableException($"{options.Name} is not configured with a model.");
        return model.Trim();
    }

    public static int ResolveMaxOutputTokens(AIRequest request, AIProviderOptions options)
    {
        var value = request.MaxOutputTokens ?? options.DefaultMaxOutputTokens;
        if (value is < 1 or > 32_768)
            throw new ArgumentOutOfRangeException(nameof(request), "Maximum output tokens must be between 1 and 32768.");
        return value;
    }

    public static void ValidateRequest(AIRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.UserPrompt))
            throw new ArgumentException("An AI user prompt is required.", nameof(request));
        if ((request.SystemPrompt?.Length ?? 0) + request.UserPrompt.Length > MaximumPromptCharacters)
            throw new ArgumentException("The combined AI prompt exceeds the 100000-character limit.", nameof(request));
        if (request.JsonSchemaJson is { Length: > MaximumJsonSchemaCharacters })
            throw new ArgumentException("The JSON schema exceeds the supported size limit.", nameof(request));
    }

    public static JsonElement? ParseJsonSchema(AIRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.JsonSchemaJson))
            return null;

        try
        {
            using var document = JsonDocument.Parse(request.JsonSchemaJson, new JsonDocumentOptions { MaxDepth = 32 });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new ArgumentException("A structured-output JSON schema must be a JSON object.", nameof(request));
            return document.RootElement.Clone();
        }
        catch (JsonException exception)
        {
            throw new ArgumentException("The structured-output JSON schema is invalid JSON.", nameof(request), exception);
        }
    }

    public static void ValidateStructuredResponse(string content, bool structuredOutput, string providerName)
    {
        if (!structuredOutput) return;
        try
        {
            using var document = JsonDocument.Parse(content, new JsonDocumentOptions { MaxDepth = 64 });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new AIProviderUnavailableException($"{providerName} returned structured output that was not a JSON object.");
        }
        catch (JsonException exception)
        {
            throw new AIProviderUnavailableException($"{providerName} returned invalid structured JSON.", exception);
        }
    }

    public static Uri CreateEndpoint(AIProviderOptions options, string defaultBaseAddress, string relativePath, bool allowHttpLoopback = false)
    {
        var baseUri = options.Endpoint ?? new Uri(defaultBaseAddress, UriKind.Absolute);
        if (!baseUri.IsAbsoluteUri || baseUri.UserInfo.Length > 0 || !string.IsNullOrEmpty(baseUri.Query) || !string.IsNullOrEmpty(baseUri.Fragment))
            throw new AIProviderUnavailableException($"{options.Name} endpoint configuration is invalid.");

        var secure = baseUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        var localHttp = allowHttpLoopback &&
            baseUri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
            IsLoopbackHost(baseUri.Host);
        if (!secure && !localHttp)
            throw new AIProviderUnavailableException($"{options.Name} requires HTTPS; plain HTTP is permitted only for a loopback Ollama endpoint.");

        var normalizedBase = new Uri(baseUri.AbsoluteUri.TrimEnd('/') + "/", UriKind.Absolute);
        return new Uri(normalizedBase, relativePath.TrimStart('/'));
    }

    public static async Task<T> SendAsync<T>(
        HttpClient client,
        HttpRequestMessage request,
        AIProviderOptions options,
        CancellationToken cancellationToken,
        Func<HttpResponseMessage, CancellationToken, Task<T>> onSuccess,
        int? timeoutSeconds = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(onSuccess);

        var timeout = timeoutSeconds ?? options.TimeoutSeconds;
        if (timeout is < 1 or > 300)
            throw new AIProviderUnavailableException($"{options.Name} timeout must be between 1 and 300 seconds.");

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(TimeSpan.FromSeconds(timeout));

        try
        {
            using var response = await client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeoutSource.Token);

            if (!response.IsSuccessStatusCode)
                throw new AIProviderUnavailableException($"{options.Name} returned HTTP {(int)response.StatusCode}.");

            return await onSuccess(response, timeoutSource.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new AIProviderUnavailableException($"{options.Name} request timed out.");
        }
        catch (HttpRequestException exception)
        {
            throw new AIProviderUnavailableException($"{options.Name} could not be reached.", exception);
        }
    }

    public static async Task<string> ReadBodyAsync(HttpResponseMessage response, AIProviderOptions options, CancellationToken cancellationToken)
    {
        var limit = options.MaxResponseBytes;
        if (limit is < 1_024 or > MaximumAllowedResponseBytes)
            throw new AIProviderUnavailableException($"{options.Name} maximum response size must be between 1024 bytes and 10 MiB.");
        if (response.Content.Headers.ContentLength is long contentLength && contentLength > limit)
            throw new AIProviderUnavailableException($"{options.Name} response exceeded the configured size limit.");

        await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await input.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (read == 0) break;
            if (output.Length + read > limit)
                throw new AIProviderUnavailableException($"{options.Name} response exceeded the configured size limit.");
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }

        try
        {
            return new UTF8Encoding(false, true).GetString(output.GetBuffer(), 0, checked((int)output.Length));
        }
        catch (DecoderFallbackException exception)
        {
            throw new AIProviderUnavailableException($"{options.Name} returned a response that was not valid UTF-8.", exception);
        }
    }

    public static HttpRequestMessage CreateJsonRequest(HttpMethod method, Uri endpoint, object payload)
    {
        var request = new HttpRequestMessage(method, endpoint);
        request.Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(payload));
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        return request;
    }

    public static bool IsLoopbackHost(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return true;
        return IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address);
    }
}
