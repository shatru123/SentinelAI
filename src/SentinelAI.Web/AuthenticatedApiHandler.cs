using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Components.Authorization;

namespace SentinelAI.Web;

public sealed class AuthenticatedApiHandler(IHttpContextAccessor httpContextAccessor, IConfiguration configuration, AuthenticationStateProvider authenticationStateProvider) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var state = await authenticationStateProvider.GetAuthenticationStateAsync();
        var principal = state.User;
        if (principal.Identity?.IsAuthenticated == true)
        {
            var context = httpContextAccessor.HttpContext;
            var accessToken = context is null ? null : await context.GetTokenAsync("access_token");
            if (!string.IsNullOrWhiteSpace(accessToken)) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            else if (configuration.GetValue<bool>("Api:UseDevelopmentHeaders") || configuration.GetValue<bool>("Authentication:UseDevelopmentHeaders"))
            {
                AddClaimHeader(request, "X-Tenant-Id", principal.FindFirstValue("tenant_id"));
                AddClaimHeader(request, "X-User-Id", principal.FindFirstValue(ClaimTypes.NameIdentifier));
                AddClaimHeader(request, "X-Role", principal.FindFirstValue(ClaimTypes.Role));
                AddClaimHeader(request, "X-User-Name", principal.Identity.Name);
            }
        }
        return await base.SendAsync(request, cancellationToken);
    }

    private static void AddClaimHeader(HttpRequestMessage request, string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) request.Headers.TryAddWithoutValidation(name, value);
    }
}
