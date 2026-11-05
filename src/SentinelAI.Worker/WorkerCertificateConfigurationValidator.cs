using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace SentinelAI.Worker;

public static class WorkerCertificateConfigurationValidator
{
    public static IReadOnlyList<string> Validate(IConfiguration configuration, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);
        if (environment.IsDevelopment())
            return [];

        var errors = new List<string>();
        var endpoint = configuration["Worker:ControlPlaneUrl"];
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) ||
            !uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            errors.Add("Worker:ControlPlaneUrl must be an HTTPS URL in Production.");
        if (!Guid.TryParse(configuration["Worker:TenantId"], out _))
            errors.Add("Worker:TenantId must be set to the provisioned tenant in Production.");
        if (string.IsNullOrWhiteSpace(configuration["Worker:Identity"]))
            errors.Add("Worker:Identity must be set to the immutable provisioned identity in Production.");
        if (!string.IsNullOrWhiteSpace(configuration["Worker:ControlPlaneToken"]))
            errors.Add("Worker:ControlPlaneToken is not permitted in Production; use a client certificate.");

        var certificatePaths = configuration.GetSection("Worker:ClientCertificatePaths").Get<string[]>() ?? [];
        var singlePath = configuration["Worker:ClientCertificatePath"];
        if (!string.IsNullOrWhiteSpace(singlePath))
            certificatePaths = [.. certificatePaths, singlePath];
        certificatePaths = certificatePaths.Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path => path.Trim()).Distinct(StringComparer.Ordinal).ToArray();
        if (certificatePaths.Length == 0)
            errors.Add("At least one mounted Worker:ClientCertificatePath or Worker:ClientCertificatePaths entry is required for mTLS.");
        var password = configuration["Worker:ClientCertificatePassword"];
        if (certificatePaths.Length > 0 && string.IsNullOrWhiteSpace(password))
            errors.Add("Worker:ClientCertificatePassword must be injected from the secret manager.");

        foreach (var path in certificatePaths)
        {
            if (!File.Exists(path))
            {
                errors.Add($"Worker client certificate file does not exist: {path}");
                continue;
            }
            try
            {
                using var certificate = X509CertificateLoader.LoadPkcs12FromFile(path, password, X509KeyStorageFlags.EphemeralKeySet);
                if (!certificate.HasPrivateKey)
                    errors.Add($"Worker client certificate has no private key: {Path.GetFileName(path)}");
                var now = DateTime.UtcNow;
                if (certificate.NotBefore.ToUniversalTime() > now || certificate.NotAfter.ToUniversalTime() <= now)
                    errors.Add($"Worker client certificate is outside its validity period: {Path.GetFileName(path)}");
                var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
                if (eku is null || !eku.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2"))
                    errors.Add($"Worker certificate does not contain the TLS client-authentication EKU: {Path.GetFileName(path)}");
            }
            catch (Exception exception) when (exception is CryptographicException or IOException or ArgumentException)
            {
                errors.Add($"Worker client certificate could not be loaded: {Path.GetFileName(path)}");
            }
        }

        if (errors.Count > 0)
            throw new InvalidOperationException("Production worker configuration is unsafe or incomplete:" + Environment.NewLine +
                string.Join(Environment.NewLine, errors.Select(error => "- " + error)));
        return certificatePaths;
    }
}
