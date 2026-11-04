using System.Net;
using System.Text;
using System.Text.Json;
using SentinelAI.AI.Abstractions;
using SentinelAI.AI.Anthropic;
using SentinelAI.AI.Ollama;
using SentinelAI.AI.OpenAI;

namespace SentinelAI.UnitTests;

public sealed class AIProviderTests
{
    private const string JsonSchema = """{"type":"object","properties":{"summary":{"type":"string"}},"required":["summary"],"additionalProperties":false}""";

    [Fact]
    public async Task OpenAI_uses_responses_api_and_preserves_usage_and_response_provenance()
    {
        var handler = new StubHandler(async (request, token) =>
        {
            Assert.Equal("/v1/responses", request.RequestUri!.AbsolutePath);
            Assert.Equal("Bearer test-openai-key", request.Headers.Authorization!.ToString());
            using var payload = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            Assert.Equal("gpt-test", payload.RootElement.GetProperty("model").GetString());
            Assert.Equal("json_schema", payload.RootElement.GetProperty("text").GetProperty("format").GetProperty("type").GetString());
            Assert.False(payload.RootElement.GetProperty("store").GetBoolean());
            return JsonResponse("""{"id":"resp_test_1","model":"gpt-test","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"{"summary":"review required"}"}]}],"usage":{"input_tokens":31,"output_tokens":9}}""");
        });
        using var client = new HttpClient(handler);
        var provider = new OpenAIProvider(client, new AIProviderOptions(
            "openai", "gpt-test", new Uri("https://api.openai.com/v1"), "test-openai-key"));

        var result = await provider.AnalyzeAsync(new AIRequest(
            "You are an advisory security analyst.",
            "Explain this evidence.",
            JsonSchemaJson: JsonSchema));

        Assert.Equal("openai", result.Provider);
        Assert.Equal("gpt-test", result.Model);
        Assert.Equal("""{"summary":"review required"}""", result.Content);
        Assert.Equal(31, result.InputTokens);
        Assert.Equal(9, result.OutputTokens);
        Assert.Equal("resp_test_1", result.ResponseId);
        Assert.Equal("completed", result.FinishReason);
        Assert.True(result.StructuredOutput);
    }

    [Fact]
    public async Task Anthropic_uses_messages_api_and_anthropic_headers()
    {
        var handler = new StubHandler(async (request, token) =>
        {
            Assert.Equal("/v1/messages", request.RequestUri!.AbsolutePath);
            Assert.Equal("test-anthropic-key", request.Headers.GetValues("x-api-key").Single());
            Assert.Equal("2023-06-01", request.Headers.GetValues("anthropic-version").Single());
            using var payload = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            Assert.Equal("claude-test", payload.RootElement.GetProperty("model").GetString());
            Assert.Equal("json_schema", payload.RootElement.GetProperty("output_config").GetProperty("format").GetProperty("type").GetString());
            return JsonResponse("""{"id":"msg_test_1","type":"message","model":"claude-test","content":[{"type":"text","text":"{"summary":"review required"}"}],"stop_reason":"end_turn","usage":{"input_tokens":21,"output_tokens":8}}""");
        });
        using var client = new HttpClient(handler);
        var provider = new AnthropicProvider(client, new AIProviderOptions(
            "anthropic", "claude-test", new Uri("https://api.anthropic.com"), "test-anthropic-key"));

        var result = await provider.AnalyzeAsync(new AIRequest(
            "You are an advisory security analyst.",
            "Explain this evidence.",
            JsonSchemaJson: JsonSchema));

        Assert.Equal("anthropic", result.Provider);
        Assert.Equal("claude-test", result.Model);
        Assert.Equal("""{"summary":"review required"}""", result.Content);
        Assert.Equal(21, result.InputTokens);
        Assert.Equal(8, result.OutputTokens);
        Assert.Equal("msg_test_1", result.ResponseId);
        Assert.Equal("end_turn", result.FinishReason);
        Assert.True(result.StructuredOutput);
    }

    [Fact]
    public async Task Ollama_uses_non_streaming_chat_and_local_structured_output()
    {
        var handler = new StubHandler(async (request, token) =>
        {
            Assert.Equal("/api/chat", request.RequestUri!.AbsolutePath);
            using var payload = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            Assert.False(payload.RootElement.GetProperty("stream").GetBoolean());
            Assert.Equal("llama-test", payload.RootElement.GetProperty("model").GetString());
            Assert.Equal("object", payload.RootElement.GetProperty("format").GetProperty("type").GetString());
            return JsonResponse("""{"model":"llama-test","created_at":"2026-11-04T02:00:00Z","message":{"role":"assistant","content":"{"summary":"review required"}"},"done":true,"done_reason":"stop","prompt_eval_count":44,"eval_count":12}""");
        });
        using var client = new HttpClient(handler);
        var provider = new OllamaProvider(client, new AIProviderOptions(
            "ollama", "llama-test", new Uri("http://127.0.0.1:11434"), null));

        var result = await provider.AnalyzeAsync(new AIRequest(
            "You are an advisory security analyst.",
            "Explain this evidence.",
            JsonSchemaJson: JsonSchema));

        Assert.Equal("ollama", result.Provider);
        Assert.Equal("llama-test", result.Model);
        Assert.Equal("""{"summary":"review required"}""", result.Content);
        Assert.Equal(44, result.InputTokens);
        Assert.Equal(12, result.OutputTokens);
        Assert.Null(result.ResponseId);
        Assert.Equal("stop", result.FinishReason);
        Assert.True(result.StructuredOutput);
    }

    [Fact]
    public async Task Provider_errors_do_not_echo_upstream_response_body()
    {
        var handler = new StubHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized)
        {
            Content = new StringContent("sensitive upstream detail and credential echo")
        }));
        using var client = new HttpClient(handler);
        var provider = new OpenAIProvider(client, new AIProviderOptions(
            "openai", "gpt-test", new Uri("https://api.openai.com/v1"), "bad-key"));

        var exception = await Assert.ThrowsAsync<AIProviderUnavailableException>(() =>
            provider.AnalyzeAsync(new AIRequest("System", "User prompt")));

        Assert.Contains("HTTP 401", exception.Message);
        Assert.DoesNotContain("sensitive upstream detail", exception.Message);
        Assert.DoesNotContain("credential echo", exception.Message);
    }

    [Fact]
    public async Task Provider_requests_observe_the_configured_timeout()
    {
        var handler = new StubHandler(async (_, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        using var client = new HttpClient(handler);
        var provider = new OpenAIProvider(client, new AIProviderOptions(
            "openai", "gpt-test", new Uri("https://api.openai.com/v1"), "test-key", TimeoutSeconds: 1));

        var exception = await Assert.ThrowsAsync<AIProviderUnavailableException>(() =>
            provider.AnalyzeAsync(new AIRequest("System", "User prompt")));

        Assert.Contains("timed out", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Provider_response_body_is_bounded_before_json_parsing()
    {
        var oversized = new string('x', 1_200);
        var handler = new StubHandler((_, _) => Task.FromResult(JsonResponse(oversized)));
        using var client = new HttpClient(handler);
        var provider = new OpenAIProvider(client, new AIProviderOptions(
            "openai", "gpt-test", new Uri("https://api.openai.com/v1"), "test-key", MaxResponseBytes: 1_024));

        var exception = await Assert.ThrowsAsync<AIProviderUnavailableException>(() =>
            provider.AnalyzeAsync(new AIRequest("System", "User prompt")));

        Assert.Contains("size limit", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Provider_factory_is_case_insensitive_and_rejects_unknown_providers()
    {
        var factory = new AIProviderFactory([
            new StubProvider("openai"),
            new StubProvider("ollama"),
            new StubProvider("anthropic")
        ]);

        Assert.Equal(new[] { "anthropic", "ollama", "openai" }, factory.GetNames());
        Assert.Equal("openai", factory.Get("OpenAI").Name);
        Assert.Throws<AIProviderUnavailableException>(() => factory.Get("unknown"));
    }

    [Fact]
    public async Task Unconfigured_provider_is_not_reported_healthy()
    {
        using var client = new HttpClient(new StubHandler((_, _) =>
            throw new InvalidOperationException("An unconfigured provider must not make a network request.")));
        var provider = new OpenAIProvider(client, new AIProviderOptions("openai", "", null, null));

        Assert.False(provider.IsConfigured);
        Assert.False(await provider.IsHealthyAsync());
    }

    private static HttpResponseMessage JsonResponse(string json)
        => new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

    private sealed class StubHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => send(request, cancellationToken);
    }

    private sealed class StubProvider(string name) : IAIProvider
    {
        public string Name => name;
        public bool IsConfigured => true;
        public Task<AIResponse> AnalyzeAsync(AIRequest request, CancellationToken cancellationToken = default)
            => Task.FromResult(new AIResponse(Name, "test", "test", null, null));
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(true);
    }
}
