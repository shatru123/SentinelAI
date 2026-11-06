using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using SentinelAI.Api;

namespace SentinelAI.IntegrationTests;

public sealed class ProductionConfigurationValidatorTests
{
    [Fact]
    public void Production_rejects_missing_or_development_configuration()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();
        var exception = Assert.Throws<InvalidOperationException>(() =>
            ProductionConfigurationValidator.Validate(configuration, new TestEnvironment("Production")));

        Assert.Contains("Authentication:Authority", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Database:Provider", exception.Message, StringComparison.Ordinal);
        Assert.Contains("WorkerAuthentication:Mode", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("replace-with", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Production_accepts_explicit_secret_managed_and_trusted_configuration()
    {
        var caPath = Path.GetTempFileName();
        try
        {
            var values = new Dictionary<string, string?>
            {
                ["Authentication:Authority"] = "https://identity.example.com/",
                ["Authentication:Audience"] = "sentinelai-api",
                ["Database:Provider"] = "Postgres",
                ["Database:ApplyMigrations"] = "false",
                ["ConnectionStrings:SentinelAI"] = "Host=postgres.internal;Database=sentinelai;Username=app;Password=managed-secret",
                ["Messaging:Mode"] = "RabbitMq",
                ["RabbitMQ:Host"] = "rabbitmq.internal",
                ["RabbitMQ:Username"] = "sentinelai-app",
                ["RabbitMQ:Password"] = "managed-secret",
                ["Artifacts:Provider"] = "S3",
                ["Artifacts:S3:Bucket"] = "sentinelai-evidence-prod",
                ["Artifacts:S3:Region"] = "ap-south-1",
                ["Artifacts:S3:ServerSideEncryption"] = "aws:kms",
                ["Artifacts:S3:KmsKeyId"] = "alias/sentinelai-evidence",
                ["WorkerAuthentication:Mode"] = "Mtls",
                ["WorkerAuthentication:TrustedRootCertificatePath"] = caPath,
                ["WorkerAuthentication:ServerCertificatePath"] = caPath,
                ["WorkerAuthentication:ServerCertificatePassword"] = "managed-certificate-password",
                ["Security:AllowedOrigins:0"] = "https://sentinelai.example.com",
                ["ReverseProxy:KnownProxies:0"] = "10.0.0.10",
                ["Security:RequireHttps"] = "true",
                ["AllowedHosts"] = "sentinelai.example.com;api.sentinelai.example.com",
                ["ExternalConfig:Provider"] = "KubernetesExternalSecrets",
                ["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://otel-collector.monitoring:4317",
                ["Health:RequireHealthyWorker"] = "true"
            };
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();

            var exception = Record.Exception(() =>
                ProductionConfigurationValidator.Validate(configuration, new TestEnvironment("Production")));

            Assert.Null(exception);
        }
        finally
        {
            File.Delete(caPath);
        }
    }

    [Fact]
    public void Production_rejects_automatic_migrations_and_default_broker_credentials()
    {
        var caPath = Path.GetTempFileName();
        try
        {
            var values = new Dictionary<string, string?>
            {
                ["Authentication:Authority"] = "https://identity.example.com/",
                ["Authentication:Audience"] = "sentinelai-api",
                ["Database:Provider"] = "Postgres",
                ["Database:ApplyMigrations"] = "true",
                ["ConnectionStrings:SentinelAI"] = "Host=db;Database=sentinelai;Username=app;Password=secret",
                ["Messaging:Mode"] = "RabbitMq",
                ["RabbitMQ:Host"] = "rabbitmq.internal",
                ["RabbitMQ:Username"] = "sentinelai",
                ["RabbitMQ:Password"] = "sentinelai",
                ["Artifacts:Provider"] = "S3",
                ["Artifacts:S3:Bucket"] = "bucket",
                ["Artifacts:S3:Region"] = "ap-south-1",
                ["Artifacts:S3:ServerSideEncryption"] = "AES256",
                ["WorkerAuthentication:Mode"] = "Mtls",
                ["WorkerAuthentication:TrustedRootCertificatePath"] = caPath,
                ["WorkerAuthentication:CertificateBindings:AA11:Identity"] = "worker-a",
                ["WorkerAuthentication:CertificateBindings:AA11:TenantId"] = Guid.NewGuid().ToString(),
                ["Security:AllowedOrigins:0"] = "https://sentinelai.example.com",
                ["ReverseProxy:KnownProxies:0"] = "10.0.0.10",
                ["Security:RequireHttps"] = "true",
                ["AllowedHosts"] = "sentinelai.example.com",
                ["ExternalConfig:Provider"] = "KubernetesExternalSecrets",
                ["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://otel-collector.monitoring:4317"
            };
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();

            var exception = Assert.Throws<InvalidOperationException>(() =>
                ProductionConfigurationValidator.Validate(configuration, new TestEnvironment("Production")));

            Assert.Contains("Database:ApplyMigrations", exception.Message, StringComparison.Ordinal);
            Assert.Contains("RabbitMQ:Password", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(caPath);
        }
    }

    [Fact]
    public void Development_does_not_require_production_secrets_or_infrastructure()
    {
        var configuration = new ConfigurationBuilder().Build();

        var exception = Record.Exception(() =>
            ProductionConfigurationValidator.Validate(configuration, new TestEnvironment("Development")));

        Assert.Null(exception);
    }

    [Fact]
    public void Migration_mode_accepts_database_only_configuration_without_http_or_worker_secrets()
    {
        var values = new Dictionary<string, string?>
        {
            ["Database:Provider"] = "Postgres",
            ["Database:ApplyMigrations"] = "false",
            ["ConnectionStrings:SentinelAI"] = "Host=postgres.internal;Database=sentinelai;Username=migrator;Password=managed-secret"
        };
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();

        var exception = Record.Exception(() =>
            ProductionConfigurationValidator.ValidateMigrationConfiguration(configuration, new TestEnvironment("Production")));

        Assert.Null(exception);
    }

    [Fact]
    public void Migration_mode_rejects_missing_or_unsafe_database_configuration()
    {
        var cases = new[]
        {
            (Values: new Dictionary<string, string?> { ["Database:Provider"] = "InMemory" }, Expected: "Database:Provider"),
            (Values: new Dictionary<string, string?> { ["Database:Provider"] = "Postgres", ["Database:ApplyMigrations"] = "false" }, Expected: "ConnectionStrings:SentinelAI"),
            (Values: new Dictionary<string, string?> { ["Database:Provider"] = "Postgres", ["Database:ApplyMigrations"] = "true", ["ConnectionStrings:SentinelAI"] = "Host=db;Database=sentinelai;Username=migrator;Password=secret" }, Expected: "Database:ApplyMigrations")
        };

        foreach (var testCase in cases)
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(testCase.Values).Build();
            var exception = Assert.Throws<InvalidOperationException>(() =>
                ProductionConfigurationValidator.ValidateMigrationConfiguration(configuration, new TestEnvironment("Production")));

            Assert.Contains(testCase.Expected, exception.Message, StringComparison.Ordinal);
        }
    }

    private sealed class TestEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "SentinelAI.IntegrationTests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
