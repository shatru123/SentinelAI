using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace SentinelAI.Api;

public sealed class DevelopmentAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Guid.TryParse(Request.Headers["X-Tenant-Id"].FirstOrDefault(), out var tenantId) || !Guid.TryParse(Request.Headers["X-User-Id"].FirstOrDefault(), out var userId))
            return Task.FromResult(AuthenticateResult.NoResult());
        var role = Request.Headers["X-Role"].FirstOrDefault() ?? "Viewer";
        if (!Enum.TryParse<SentinelAI.Domain.UserRole>(role, true, out _)) return Task.FromResult(AuthenticateResult.Fail("Invalid development role."));
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name, Request.Headers["X-User-Name"].FirstOrDefault() ?? userId.ToString()),
            new Claim("tenant_id", tenantId.ToString()),
            new Claim(ClaimTypes.Role, role)
        };
        if (role.Equals("Worker", StringComparison.OrdinalIgnoreCase))
            claims.Add(new Claim("worker_id", Request.Headers["X-Worker-Id"].FirstOrDefault() ?? string.Empty));
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name)), Scheme.Name)));
    }
}
