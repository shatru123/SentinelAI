using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Components.Authorization;

namespace SentinelAI.Web;

public static class SentinelApiAuthentication
{
    public const string AccessTokenClaim = "sentinelai_access_token";
}

public sealed class AuthenticatedApiTokenStore
{
    public string? AccessToken { get; private set; }
    public void Set(string accessToken) => AccessToken = accessToken;
}

public sealed class AuthenticatedApiHandler(
    IHttpContextAccessor httpContextAccessor,
    IConfiguration configuration,
    AuthenticationStateProvider authenticationStateProvider,
    AuthenticatedApiTokenStore tokenStore,
    ILogger<AuthenticatedApiHandler> logger) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var context = httpContextAccessor.HttpContext;
        ClaimsPrincipal principal;
        if (context is not null)
        {
            principal = context.User;
        }
        else
        {
            try
            {
                principal = (await authenticationStateProvider.GetAuthenticationStateAsync()).User;
            }
            catch (InvalidOperationException)
            {
                logger.LogDebug("Interactive authentication state is not available for this API request.");
                principal = new ClaimsPrincipal(new ClaimsIdentity());
            }
        }

        if (principal.Identity?.IsAuthenticated == true)
        {
            var accessToken = context is null
                ? principal.FindFirstValue(SentinelApiAuthentication.AccessTokenClaim) ?? tokenStore.AccessToken
                : await context.GetTokenAsync("access_token")
                    ?? principal.FindFirstValue(SentinelApiAuthentication.AccessTokenClaim)
                    ?? tokenStore.AccessToken;
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                tokenStore.Set(accessToken);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            }
            else if (configuration.GetValue<bool>("Api:UseDevelopmentHeaders") || configuration.GetValue<bool>("Authentication:UseDevelopmentHeaders"))
            {
                AddClaimHeader(request, "X-Tenant-Id", principal.FindFirstValue("tenant_id"));
                AddClaimHeader(request, "X-User-Id", principal.FindFirstValue(ClaimTypes.NameIdentifier));
                AddClaimHeader(request, "X-Role", principal.FindFirstValue(ClaimTypes.Role));
                AddClaimHeader(request, "X-User-Name", principal.Identity.Name);
            }
            else
            {
                logger.LogWarning("Authenticated API request was blocked because no bearer token is available outside development header mode.");
                throw new ApiAuthenticationException();
            }
        }
        return await base.SendAsync(request, cancellationToken);
    }

    private static void AddClaimHeader(HttpRequestMessage request, string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) request.Headers.TryAddWithoutValidation(name, value);
    }
}
