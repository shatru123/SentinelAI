using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace SentinelAI.Web;

public static class WebProductionConfigurationValidator
{
    public static void Validate(IConfiguration configuration, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);
        if (!environment.IsProduction()) return;

        var errors = new List<string>();
        RequireHttps(configuration["Authentication:Authority"], "Authentication:Authority", errors);
        RequireValue(configuration["Authentication:ClientId"], "Authentication:ClientId", errors);
        RequireValue(configuration["Authentication:ClientSecret"], "Authentication:ClientSecret", errors);
        RequireHttps(configuration["Api:BaseUrl"], "Api:BaseUrl", errors);

        var allowedHosts = configuration["AllowedHosts"];
        if (string.IsNullOrWhiteSpace(allowedHosts) || allowedHosts.Trim() == "*" ||
            allowedHosts.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Length == 0)
            errors.Add("AllowedHosts must be an explicit host allow-list in Production.");

        var knownProxies = configuration.GetSection("ReverseProxy:KnownProxies").Get<string[]>() ?? [];
        if (knownProxies.Length == 0 || knownProxies.Any(proxy => !System.Net.IPAddress.TryParse(proxy, out _)))
            errors.Add("ReverseProxy:KnownProxies must list the exact trusted proxy IP addresses.");
        if (!configuration.GetValue<bool>("Security:RequireHttps"))
            errors.Add("Security:RequireHttps must be true in Production.");

        if (configuration.GetValue<bool>("Api:UseDevelopmentHeaders") ||
            configuration.GetValue<bool>("Authentication:UseDevelopmentHeaders"))
            errors.Add("Development identity headers must be disabled in Production.");

        if (errors.Count > 0)
            throw new InvalidOperationException("Production Web configuration is unsafe or incomplete:" + Environment.NewLine +
                string.Join(Environment.NewLine, errors.Select(error => "- " + error)));
    }

    private static void RequireHttps(string? value, string key, ICollection<string> errors)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            !uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            errors.Add($"{key} must be an absolute HTTPS URL.");
    }

    private static void RequireValue(string? value, string key, ICollection<string> errors)
    {
        if (string.IsNullOrWhiteSpace(value))
            errors.Add($"{key} is required.");
    }
}
