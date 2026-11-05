using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
        RequireNonDefaultSecret(configuration["Authentication:ClientSecret"], "Authentication:ClientSecret", errors);
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

        ValidateDataProtection(configuration, errors);

        if (errors.Count > 0)
            throw new InvalidOperationException("Production Web configuration is unsafe or incomplete:" + Environment.NewLine +
                string.Join(Environment.NewLine, errors.Select(error => "- " + error)));
    }

    private static void ValidateDataProtection(IConfiguration configuration, ICollection<string> errors)
    {
        var keyRingPath = configuration["DataProtection:KeyRingPath"];
        if (string.IsNullOrWhiteSpace(keyRingPath) || !Path.IsPathFullyQualified(keyRingPath) ||
            !Directory.Exists(keyRingPath))
        {
            errors.Add("DataProtection:KeyRingPath must point to a mounted persistent shared directory.");
        }
        else
        {
            var probePath = Path.Combine(keyRingPath, $".sentinelai-write-check-{Guid.NewGuid():N}");
            try
            {
                using (File.Create(probePath)) { }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                errors.Add("DataProtection:KeyRingPath must be writable by the Web application identity.");
            }
            finally
            {
                try { if (File.Exists(probePath)) File.Delete(probePath); }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { }
            }
        }

        var certificatePath = configuration["DataProtection:CertificatePath"];
        var password = configuration["DataProtection:CertificatePassword"];
        if (string.IsNullOrWhiteSpace(certificatePath) || !Path.IsPathFullyQualified(certificatePath) || !File.Exists(certificatePath))
        {
            errors.Add("DataProtection:CertificatePath must point to a mounted key-encryption certificate.");
            return;
        }
        if (string.IsNullOrWhiteSpace(password) || IsDefaultSecret(password))
        {
            errors.Add("DataProtection:CertificatePassword must be injected from the external secret provider.");
            return;
        }

        try
        {
            using var certificate = X509CertificateLoader.LoadPkcs12FromFile(
                certificatePath, password, X509KeyStorageFlags.EphemeralKeySet);
            if (!certificate.HasPrivateKey)
                errors.Add("The Data Protection encryption certificate must include its private key.");
            var now = DateTime.UtcNow;
            if (certificate.NotBefore.ToUniversalTime() > now || certificate.NotAfter.ToUniversalTime() <= now)
                errors.Add("The Data Protection encryption certificate must be currently valid.");
        }
        catch (Exception exception) when (exception is CryptographicException or IOException or ArgumentException)
        {
            errors.Add("The Data Protection encryption certificate could not be loaded from the mounted secret.");
        }
    }

    private static bool IsDefaultSecret(string value)
        => value.Contains("replace-with", StringComparison.OrdinalIgnoreCase) ||
           value.Equals("sentinelai", StringComparison.OrdinalIgnoreCase) ||
           value.Equals("password", StringComparison.OrdinalIgnoreCase) ||
           value.Equals("placeholder", StringComparison.OrdinalIgnoreCase);

    private static void RequireNonDefaultSecret(string? value, string key, ICollection<string> errors)
    {
        if (string.IsNullOrWhiteSpace(value) || IsDefaultSecret(value))
            errors.Add($"{key} must be supplied by the external secret provider and must not use a sample/default value.");
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
