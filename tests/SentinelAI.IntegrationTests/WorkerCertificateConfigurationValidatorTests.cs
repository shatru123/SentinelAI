using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using SentinelAI.Worker;

namespace SentinelAI.IntegrationTests;

public sealed class WorkerCertificateConfigurationValidatorTests
{
    [Fact]
    public void Production_accepts_private_key_mounted_pfx_and_https_control_plane()
    {
        const string password = "worker-secret-from-secret-store";
        var path = CreatePfx(password);
        try
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Worker:ControlPlaneUrl"] = "https://api.sentinelai.example.com:8443",
                ["Worker:TenantId"] = Guid.NewGuid().ToString(),
                ["Worker:Identity"] = "worker-east-01",
                ["Worker:ClientCertificatePath"] = path,
                ["Worker:ClientCertificatePassword"] = password,
                ["ConnectionStrings:SentinelAIWorker"] = "Host=db.internal;Database=sentinelai;Username=worker;Password=secret",
                ["Messaging:Mode"] = "RabbitMq",
                ["RabbitMQ:Host"] = "rabbitmq.internal",
                ["RabbitMQ:WorkerUsername"] = "sentinelai-worker",
                ["RabbitMQ:WorkerPassword"] = "worker-broker-secret",
                ["ExternalConfig:Provider"] = "ExternalSecrets"
            }).Build();

            var paths = WorkerCertificateConfigurationValidator.Validate(configuration, new TestEnvironment("Production"));

            Assert.Single(paths);
            Assert.Equal(path, paths[0]);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Production_rejects_worker_bearer_token_even_when_certificate_is_configured()
    {
        const string password = "worker-secret-from-secret-store";
        var path = CreatePfx(password);
        try
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Worker:ControlPlaneUrl"] = "https://api.sentinelai.example.com:8443",
                ["Worker:TenantId"] = Guid.NewGuid().ToString(),
                ["Worker:Identity"] = "worker-east-01",
                ["Worker:ClientCertificatePath"] = path,
                ["Worker:ClientCertificatePassword"] = password,
                ["ConnectionStrings:SentinelAIWorker"] = "Host=db.internal;Database=sentinelai;Username=worker;Password=secret",
                ["Messaging:Mode"] = "RabbitMq",
                ["RabbitMQ:Host"] = "rabbitmq.internal",
                ["RabbitMQ:WorkerUsername"] = "sentinelai-worker",
                ["RabbitMQ:WorkerPassword"] = "worker-broker-secret",
                ["ExternalConfig:Provider"] = "ExternalSecrets",
                ["Worker:ControlPlaneToken"] = "legacy-token"
            }).Build();

            var exception = Assert.Throws<InvalidOperationException>(() =>
                WorkerCertificateConfigurationValidator.Validate(configuration, new TestEnvironment("Production")));

            Assert.Contains("Worker:ControlPlaneToken", exception.Message, StringComparison.Ordinal);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Production_requires_https_and_a_tenant_bound_identity()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Worker:ControlPlaneUrl"] = "http://api.internal:8080",
            ["Worker:Identity"] = "worker-east-01"
        }).Build();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            WorkerCertificateConfigurationValidator.Validate(configuration, new TestEnvironment("Production")));

        Assert.Contains("HTTPS", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Worker:TenantId", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Worker:ClientCertificatePaths", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Development_keeps_local_bearer_workflow_without_mtls_files()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Worker:ControlPlaneToken"] = "local-dev-token"
        }).Build();

        var paths = WorkerCertificateConfigurationValidator.Validate(configuration, new TestEnvironment("Development"));

        Assert.Empty(paths);
    }

    private static string CreatePfx(string password)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=worker-east-01", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.2") }, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(30));
        var path = Path.Combine(Path.GetTempPath(), $"sentinelai-worker-{Guid.NewGuid():N}.pfx");
        File.WriteAllBytes(path, certificate.Export(X509ContentType.Pfx, password));
        return path;
    }

    private sealed class TestEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "SentinelAI.UnitTests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
