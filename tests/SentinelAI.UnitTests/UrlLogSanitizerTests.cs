using SentinelAI.Agent.Vulnerability;

namespace SentinelAI.UnitTests;

public sealed class UrlLogSanitizerTests
{
    [Theory]
    [InlineData("https://user:password@example.com:8443/api/v1/auth?token=secret123#frag", "https://example.com:8443")]
    [InlineData("https://admin:p@ssword123@secure.corp.internal/admin/keys?api_key=xyz", "https://secure.corp.internal")]
    [InlineData("http://victim.test:8080/deep/path/with/sensitive/identifiers/12345", "http://victim.test:8080")]
    [InlineData("http://example.com:80/", "http://example.com")]
    [InlineData("https://example.com:443/", "https://example.com")]
    [InlineData("wss://user:token@socket.example.org:9001/realtime/events?session=abc#debug", "wss://socket.example.org:9001")]
    [InlineData("ws://127.0.0.1:5000/ws?token=sensitive_value", "ws://127.0.0.1:5000")]
    [InlineData("ws://echo.websocket.events/ws", "ws://echo.websocket.events")]
    public void SanitizeForLogging_removes_credentials_query_fragment_and_paths(string rawUrl, string expected)
    {
        var sanitized = UrlLogSanitizer.SanitizeForLogging(rawUrl);
        Assert.Equal(expected, sanitized);
    }

    [Theory]
    [InlineData("https://user:pass@example.com/sensitive/data?secret=true", "user")]
    [InlineData("https://user:pass@example.com/sensitive/data?secret=true", "pass")]
    [InlineData("https://user:pass@example.com/sensitive/data?secret=true", "secret")]
    [InlineData("https://user:pass@example.com/sensitive/data?secret=true", "sensitive")]
    public void SanitizeForLogging_never_contains_sensitive_substrings(string rawUrl, string forbiddenSubstring)
    {
        var sanitized = UrlLogSanitizer.SanitizeForLogging(rawUrl);
        Assert.DoesNotContain(forbiddenSubstring, sanitized, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(null, "[empty]")]
    [InlineData("", "[empty]")]
    [InlineData("   ", "[empty]")]
    [InlineData("not-a-valid-url", "[redacted-url]")]
    [InlineData("://bad-scheme", "[redacted-url]")]
    [InlineData("/relative/path?token=secret#part", "[redacted-url]")]
    public void SanitizeForLogging_handles_malformed_and_empty_inputs_safely(string? input, string expected)
    {
        var sanitized = UrlLogSanitizer.SanitizeForLogging(input);
        Assert.Equal(expected, sanitized);
    }

    [Fact]
    public void SanitizeForLogging_Uri_overload_removes_sensitive_components()
    {
        var uri = new Uri("https://operator:supersecret@app.test:8443/private/v2/tokens?auth=jwt_here#status");
        var sanitized = UrlLogSanitizer.SanitizeForLogging(uri);

        Assert.Equal("https://app.test:8443", sanitized);
        Assert.DoesNotContain("operator", sanitized);
        Assert.DoesNotContain("supersecret", sanitized);
        Assert.DoesNotContain("tokens", sanitized);
        Assert.DoesNotContain("jwt_here", sanitized);
    }

    [Fact]
    public void SanitizeForLogging_never_throws_under_fuzz_or_corrupt_data()
    {
        string[] testCases =
        [
            "",
            " ",
            "http",
            "http:",
            "http:/",
            "http://",
            "http:///",
            "http://user:pass@",
            "http://user:pass@?query=1#frag",
            "https://[::1]:9999/path?key=val",
            "https://%00%01%02%FF",
            new string('a', 10000)
        ];

        foreach (var tc in testCases)
        {
            var exception = Record.Exception(() => UrlLogSanitizer.SanitizeForLogging(tc));
            Assert.Null(exception);
        }
    }
}
