using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace SentinelAI.Api;

public static class ProductionConfigurationValidator
{
    public static void Validate(IConfiguration configuration, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        if (!environment.IsProduction())
            return;

        var errors = new List<string>();
        RequireHttps(configuration["Authentication:Authority"], "Authentication:Authority", errors);
        RequireValue(configuration["Authentication:Audience"], "Authentication:Audience", errors);
        RequireValue(configuration["ConnectionStrings:SentinelAI"], "ConnectionStrings:SentinelAI", errors);

        var databaseProvider = configuration["Database:Provider"];
        if (!string.Equals(databaseProvider, "Postgres", StringComparison.OrdinalIgnoreCase))
            errors.Add("Database:Provider must be Postgres in Production.");
        if (configuration.GetValue<bool>("Database:ApplyMigrations"))
            errors.Add("Database:ApplyMigrations must be false in Production; run the dedicated migration job.");

        var messagingMode = configuration["Messaging:Mode"];
        if (!string.Equals(messagingMode, "RabbitMq", StringComparison.OrdinalIgnoreCase))
            errors.Add("Messaging:Mode must be RabbitMq in Production.");
        RequireNonLocalValue(configuration["RabbitMQ:Host"], "RabbitMQ:Host", errors);
        RequireValue(configuration["RabbitMQ:Username"], "RabbitMQ:Username", errors);
        RequireNonDefaultSecret(configuration["RabbitMQ:Password"], "RabbitMQ:Password", errors);

        if (!string.Equals(configuration["Artifacts:Provider"], "S3", StringComparison.OrdinalIgnoreCase))
            errors.Add("Artifacts:Provider must be S3 in Production; local filesystem storage is Development-only.");
        RequireValue(configuration["Artifacts:S3:Bucket"], "Artifacts:S3:Bucket", errors);
        RequireValue(configuration["Artifacts:S3:Region"], "Artifacts:S3:Region", errors);
        var encryption = configuration["Artifacts:S3:ServerSideEncryption"];
        if (!string.Equals(encryption, "AES256", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(encryption, "aws:kms", StringComparison.OrdinalIgnoreCase))
            errors.Add("Artifacts:S3:ServerSideEncryption must be AES256 or aws:kms.");
        if (string.Equals(encryption, "aws:kms", StringComparison.OrdinalIgnoreCase))
            RequireValue(configuration["Artifacts:S3:KmsKeyId"], "Artifacts:S3:KmsKeyId", errors);

        if (!string.Equals(configuration["WorkerAuthentication:Mode"], "Mtls", StringComparison.OrdinalIgnoreCase))
            errors.Add("WorkerAuthentication:Mode must be Mtls in Production; bearer-token worker authentication is Development-only.");
        var caPath = configuration["WorkerAuthentication:TrustedRootCertificatePath"];
        RequireFile(caPath, "WorkerAuthentication:TrustedRootCertificatePath", errors);
        RequireFile(configuration["WorkerAuthentication:ServerCertificatePath"], "WorkerAuthentication:ServerCertificatePath", errors);
        RequireNonDefaultSecret(configuration["WorkerAuthentication:ServerCertificatePassword"], "WorkerAuthentication:ServerCertificatePassword", errors);
        if (!string.IsNullOrWhiteSpace(configuration["Authentication:WorkerToken"]) ||
            configuration.GetSection("Authentication:WorkerCredentials").GetChildren().Any())
            errors.Add("Static worker bearer credentials must not be configured in Production.");
        if (configuration.GetValue<bool>("Authentication:UseDevelopmentHeaders"))
            errors.Add("Authentication:UseDevelopmentHeaders must be false in Production.");
        if (configuration.GetValue<bool>("Authorization:AllowAdminSelfApproval"))
            errors.Add("Authorization:AllowAdminSelfApproval must be false in Production.");

        var allowedOrigins = configuration.GetSection("Security:AllowedOrigins").Get<string[]>() ?? [];
        if (allowedOrigins.Length == 0 || allowedOrigins.Any(origin => !IsHttpsOrigin(origin)))
            errors.Add("Security:AllowedOrigins must contain one or more explicit HTTPS origins; wildcards are not allowed.");

        var knownProxies = configuration.GetSection("ReverseProxy:KnownProxies").Get<string[]>() ?? [];
        if (knownProxies.Length == 0 || knownProxies.Any(proxy => !IPAddress.TryParse(proxy, out _)))
            errors.Add("ReverseProxy:KnownProxies must list the exact trusted proxy IP addresses.");
        if (!configuration.GetValue<bool>("Security:RequireHttps"))
            errors.Add("Security:RequireHttps must be true in Production.");

        var allowedHosts = configuration["AllowedHosts"];
        if (string.IsNullOrWhiteSpace(allowedHosts) || allowedHosts.Trim() == "*" ||
            allowedHosts.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Length == 0)
            errors.Add("AllowedHosts must be an explicit host allow-list in Production.");

        RequireValue(configuration["Secrets:Provider"], "Secrets:Provider", errors);
        RequireNonLocalValue(configuration["OTEL_EXPORTER_OTLP_ENDPOINT"], "OTEL_EXPORTER_OTLP_ENDPOINT", errors);

        if (errors.Count > 0)
            throw new InvalidOperationException("Production configuration is unsafe or incomplete:" + Environment.NewLine +
                string.Join(Environment.NewLine, errors.Select(error => "- " + error)));
    }

    private static bool IsHttpsOrigin(string? value)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
           uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
           uri.AbsolutePath == "/" && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment);

    private static void RequireHttps(string? value, string key, ICollection<string> errors)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            !uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            errors.Add($"{key} must be an absolute HTTPS URL.");
    }

    private static void RequireFile(string? value, string key, ICollection<string> errors)
    {
        if (string.IsNullOrWhiteSpace(value) || !File.Exists(value))
            errors.Add($"{key} must point to a mounted CA certificate file.");
    }

    private static void RequireValue(string? value, string key, ICollection<string> errors)
    {
        if (string.IsNullOrWhiteSpace(value))
            errors.Add($"{key} is required.");
    }

    private static void RequireNonDefaultSecret(string? value, string key, ICollection<string> errors)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Contains("replace-with", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("sentinelai", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("password", StringComparison.OrdinalIgnoreCase))
            errors.Add($"{key} must be supplied by the external secret provider and must not use a sample/default value.");
    }

    private static void RequireNonLocalValue(string? value, string key, ICollection<string> errors)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("127.", StringComparison.Ordinal) || value.Equals("::1", StringComparison.OrdinalIgnoreCase))
            errors.Add($"{key} must identify a configured non-local Production dependency.");
    }
}
