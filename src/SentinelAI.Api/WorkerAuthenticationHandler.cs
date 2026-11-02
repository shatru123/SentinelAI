using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace SentinelAI.Api;

public sealed class WorkerAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, IConfiguration configuration)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        if (!TryGetBearerToken(header, out var token)) return Task.FromResult(AuthenticateResult.NoResult());
        var workerId = ResolveIdentity(token, configuration);
        if (workerId is null) return Task.FromResult(AuthenticateResult.Fail("The worker credential is invalid or revoked."));
        var suppliedIdentity = Request.Headers["X-Worker-Id"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(suppliedIdentity) && !suppliedIdentity.Equals(workerId, StringComparison.Ordinal))
            return Task.FromResult(AuthenticateResult.Fail("The worker identity header does not match the authenticated credential."));
        var tenant = configuration[$"Authentication:WorkerTenants:{workerId}"] ?? configuration["Authentication:WorkerTenantId"];
        if (!Guid.TryParse(tenant, out var tenantId)) return Task.FromResult(AuthenticateResult.Fail("Worker tenant mapping is not configured."));
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

    public static bool IsConfiguredWorkerToken(string authorizationHeader, IConfiguration configuration)
        => TryGetBearerToken(authorizationHeader, out var token) && ResolveIdentity(token, configuration) is not null;

    private static string? ResolveIdentity(string token, IConfiguration configuration)
    {
        if (configuration.GetSection("Authentication:RevokedWorkerTokens").GetChildren().Select(x => x.Value)
            .Concat((configuration["Authentication:RevokedWorkerTokens"] ?? string.Empty).Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Any(revoked => FixedTimeEquals(token, revoked!))) return null;
        foreach (var credential in configuration.GetSection("Authentication:WorkerCredentials").GetChildren())
        {
            if (string.IsNullOrWhiteSpace(credential.Key) || string.IsNullOrWhiteSpace(credential.Value)) continue;
            foreach (var candidate in credential.Value.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                if (FixedTimeEquals(token, candidate)) return credential.Key;
        }
        if (configuration.GetValue("Authentication:UseDevelopmentHeaders", false) && configuration.GetValue("Authentication:AllowSharedWorkerToken", false))
        {
            var shared = configuration["Authentication:WorkerToken"];
            if (!string.IsNullOrWhiteSpace(shared) && FixedTimeEquals(token, shared) && !configuration.GetSection("Authentication:RevokedWorkerTokens").GetChildren().Any(x => FixedTimeEquals(token, x.Value ?? string.Empty)))
                return configuration["Authentication:DevelopmentWorkerIdentity"] ?? "development-worker";
        }
        return null;
    }

    private static bool TryGetBearerToken(string header, out string token)
    {
        token = string.Empty;
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return false;
        token = header[7..].Trim();
        return token.Length > 0;
    }

    private static bool FixedTimeEquals(string left, string right)
        => CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(left), Encoding.UTF8.GetBytes(right));

    private static Guid DeterministicGuid(string value)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return new Guid(hash.AsSpan(0, 16));
    }
}
