using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace SentinelAI.Api;

public sealed class WorkerAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, IConfiguration configuration)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var configured = configuration["Authentication:WorkerToken"];
        var header = Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(configured) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) || !CryptographicEquals(header[7..], configured))
            return Task.FromResult(AuthenticateResult.NoResult());
        var tenant = configuration["Authentication:WorkerTenantId"];
        if (!Guid.TryParse(tenant, out var tenantId)) return Task.FromResult(AuthenticateResult.Fail("Worker tenant mapping is not configured."));
        var workerId = Request.Headers["X-Worker-Id"].FirstOrDefault() ?? "configured-worker";
        var userId = DeterministicGuid(workerId);
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name, workerId),
            new Claim("tenant_id", tenantId.ToString()),
            new Claim(ClaimTypes.Role, "Worker"),
            new Claim("worker_id", workerId)
        };
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name)), Scheme.Name)));
    }

    private static bool CryptographicEquals(string left, string right)
    {
        var leftBytes = System.Text.Encoding.UTF8.GetBytes(left); var rightBytes = System.Text.Encoding.UTF8.GetBytes(right);
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }

    private static Guid DeterministicGuid(string value) => new(System.Security.Cryptography.MD5.HashData(System.Text.Encoding.UTF8.GetBytes(value)));
}
