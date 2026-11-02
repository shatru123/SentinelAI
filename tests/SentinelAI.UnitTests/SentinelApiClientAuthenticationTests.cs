using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Contracts;
using SentinelAI.Web;

namespace SentinelAI.UnitTests;

public sealed class SentinelApiClientAuthenticationTests
{
    [Fact]
    public async Task User_A_sends_only_token_A()
    {
        var handler = new CapturingHandler();
        var client = CreateClient(handler, CreatePrincipal("token-a", "tenant-a"));

        await client.GetPageAsync<AssetResponse>("/api/v1/assets", 1, 25);

        var request = Assert.Single(handler.Requests);
        Assert.Equal("Bearer token-a", request.Authorization);
    }

    [Fact]
    public async Task Interactive_server_request_uses_the_circuit_principal_when_HttpContext_is_null()
    {
        var handler = new CapturingHandler();
        var client = CreateClient(handler, CreatePrincipal("circuit-token", "tenant-circuit"));

        await client.GetPageAsync<AssetResponse>("/api/v1/assets", 1, 25);

        var request = Assert.Single(handler.Requests);
        Assert.Equal("Bearer circuit-token", request.Authorization);
    }

    [Fact]
    public async Task User_B_sends_only_token_B()
    {
        var handler = new CapturingHandler();
        var userA = CreateClient(handler, CreatePrincipal("token-a", "tenant-a"));
        var userB = CreateClient(handler, CreatePrincipal("token-b", "tenant-b"));

        await userA.GetPageAsync<AssetResponse>("/api/v1/assets", 1, 25);
        await userB.GetPageAsync<AssetResponse>("/api/v1/assets", 1, 25);

        Assert.Equal(["Bearer token-a", "Bearer token-b"], handler.Requests.Select(x => x.Authorization).OrderBy(x => x));
    }

    [Fact]
    public async Task User_B_without_a_token_cannot_reuse_user_A_token()
    {
        var handler = new CapturingHandler();
        var userA = CreateClient(handler, CreatePrincipal("token-a", "tenant-a"));
        var userB = CreateClient(handler, CreatePrincipal(null, "tenant-b"));

        await userA.GetPageAsync<AssetResponse>("/api/v1/assets", 1, 25);
        var exception = await Assert.ThrowsAsync<SentinelApiException>(() => userB.GetPageAsync<AssetResponse>("/api/v1/assets", 1, 25));

        Assert.Equal(SentinelApiFailureKind.AuthenticationRequired, exception.Kind);
        Assert.Contains("session has expired", exception.UserMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Single(handler.Requests);
        Assert.Equal("Bearer token-a", handler.Requests.Single().Authorization);
    }

    [Fact]
    public async Task Concurrent_users_keep_their_authentication_state_isolated_when_HttpContext_is_null()
    {
        var handler = new CapturingHandler();
        var userA = CreateClient(handler, CreatePrincipal("token-a", "tenant-a"));
        var userB = CreateClient(handler, CreatePrincipal("token-b", "tenant-b"));

        await Task.WhenAll(
            userA.GetPageAsync<AssetResponse>("/api/v1/assets", 1, 25),
            userB.GetPageAsync<AssetResponse>("/api/v1/assets", 1, 25));

        Assert.Equal(["Bearer token-a", "Bearer token-b"], handler.Requests.Select(x => x.Authorization).OrderBy(x => x));
    }

    [Fact]
    public async Task Development_headers_require_both_development_environment_and_explicit_setting()
    {
        var developmentHandler = new CapturingHandler();
        var developmentClient = CreateClient(developmentHandler, CreatePrincipal(null, "tenant-dev"), "Development", useDevelopmentHeaders: true);
        await developmentClient.GetPageAsync<AssetResponse>("/api/v1/assets", 1, 25);

        var developmentRequest = Assert.Single(developmentHandler.Requests);
        Assert.Null(developmentRequest.Authorization);
        Assert.Equal("tenant-dev", developmentRequest.Headers["X-Tenant-Id"]);

        var productionHandler = new CapturingHandler();
        var productionClient = CreateClient(productionHandler, CreatePrincipal(null, "tenant-prod"), "Production", useDevelopmentHeaders: true);
        var exception = await Assert.ThrowsAsync<SentinelApiException>(() => productionClient.GetPageAsync<AssetResponse>("/api/v1/assets", 1, 25));

        Assert.Equal(SentinelApiFailureKind.AuthenticationRequired, exception.Kind);
        Assert.Empty(productionHandler.Requests);
    }

    [Fact]
    public async Task Production_without_a_bearer_token_is_rejected()
    {
        var handler = new CapturingHandler();
        var client = CreateClient(handler, CreatePrincipal(null, "tenant-prod"), "Production");

        var exception = await Assert.ThrowsAsync<SentinelApiException>(() => client.GetPageAsync<AssetResponse>("/api/v1/assets", 1, 25));

        Assert.Equal(SentinelApiFailureKind.AuthenticationRequired, exception.Kind);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Api_401_is_reported_as_session_expired_feedback()
    {
        var handler = new CapturingHandler(HttpStatusCode.Unauthorized);
        var client = CreateClient(handler, CreatePrincipal("expired-token", "tenant-a"));

        var exception = await Assert.ThrowsAsync<SentinelApiException>(() => client.GetPageAsync<AssetResponse>("/api/v1/assets", 1, 25));

        Assert.Equal(SentinelApiFailureKind.AuthenticationRequired, exception.Kind);
        Assert.Equal("Your session has expired or authentication is required. Sign in again.", exception.UserMessage);
        Assert.Equal("Bearer expired-token", Assert.Single(handler.Requests).Authorization);
    }

    private static SentinelApiClient CreateClient(
        CapturingHandler handler,
        ClaimsPrincipal principal,
        string environmentName = "Production",
        bool useDevelopmentHeaders = false)
    {
        var factory = new TestHttpClientFactory(handler);
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Api:UseDevelopmentHeaders"] = useDevelopmentHeaders.ToString()
            })
            .Build();
        return new SentinelApiClient(
            factory,
            new HttpContextAccessor(),
            new TestAuthenticationStateProvider(principal),
            new TestHostEnvironment { EnvironmentName = environmentName },
            configuration,
            NullLogger<SentinelApiClient>.Instance);
    }

    private static ClaimsPrincipal CreatePrincipal(string? accessToken, string tenantId)
    {
        var claims = new List<Claim>
        {
            new("tenant_id", tenantId),
            new(ClaimTypes.NameIdentifier, $"user-{tenantId}"),
            new(ClaimTypes.Name, $"user-{tenantId}"),
            new(ClaimTypes.Role, "Reader")
        };
        if (accessToken is not null) claims.Add(new Claim(SentinelApiAuthentication.AccessTokenClaim, accessToken));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    private sealed class TestAuthenticationStateProvider(ClaimsPrincipal principal) : AuthenticationStateProvider
    {
        public override Task<AuthenticationState> GetAuthenticationStateAsync() =>
            Task.FromResult(new AuthenticationState(principal));
    }

    private sealed class TestHttpClientFactory(CapturingHandler handler) : IHttpClientFactory
    {
        private readonly HttpClient client = new(handler) { BaseAddress = new Uri("http://sentinelai.test") };

        public HttpClient CreateClient(string name) => client;
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Production";
        public string ApplicationName { get; set; } = "SentinelAI.UnitTests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = new Microsoft.Extensions.FileProviders.NullFileProvider();
    }

    private sealed class CapturingHandler(HttpStatusCode statusCode = HttpStatusCode.OK) : HttpMessageHandler
    {
        public ConcurrentBag<CapturedRequest> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(new CapturedRequest(
                request.Headers.Authorization?.ToString(),
                request.Headers.ToDictionary(pair => pair.Key, pair => pair.Value.Single())));
            var response = new HttpResponseMessage(statusCode)
            {
                Content = statusCode == HttpStatusCode.OK
                    ? JsonContent.Create(new PagedResponse<AssetResponse>([], 1, 25, 0))
                    : new StringContent(string.Empty)
            };
            return Task.FromResult(response);
        }
    }

    private sealed record CapturedRequest(string? Authorization, IReadOnlyDictionary<string, string> Headers);
}
