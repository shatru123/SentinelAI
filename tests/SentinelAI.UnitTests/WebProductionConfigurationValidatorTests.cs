using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Hosting;
using SentinelAI.Web;

namespace SentinelAI.UnitTests;

public sealed class WebProductionConfigurationValidatorTests
{
    [Fact]
    public void Production_requires_oidc_https_api_and_trusted_proxy_configuration()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Authentication:Authority"] = "http://identity.example.com/",
            ["Authentication:ClientId"] = "sentinelai-web",
            ["Authentication:ClientSecret"] = "managed-secret",
            ["Api:BaseUrl"] = "http://api.internal",
            ["Security:RequireHttps"] = "false",
            ["AllowedHosts"] = "*",
            ["Api:UseDevelopmentHeaders"] = "true"
        }).Build();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            WebProductionConfigurationValidator.Validate(configuration, new TestEnvironment()));

        Assert.Contains("Authentication:Authority", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Api:BaseUrl", exception.Message, StringComparison.Ordinal);
        Assert.Contains("ReverseProxy:KnownProxies", exception.Message, StringComparison.Ordinal);
        Assert.Contains("AllowedHosts", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Development identity headers", exception.Message, StringComparison.Ordinal);
        Assert.Contains("DataProtection:KeyRingPath", exception.Message, StringComparison.Ordinal);
        Assert.Contains("DataProtection:CertificatePath", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Production_accepts_oidc_tls_and_shared_encrypted_data_protection_configuration()
    {
        var assets = CreateDataProtectionAssets();
        try
        {
            var configuration = CreateConfiguration(assets.KeyRingDirectory, assets.CertificatePath, assets.Password);

            var exception = Record.Exception(() =>
                WebProductionConfigurationValidator.Validate(configuration, new TestEnvironment()));

            Assert.Null(exception);
        }
        finally
        {
            assets.Dispose();
        }
    }

    [Fact]
    public void Shared_encrypted_key_ring_survives_web_replica_replacement_and_previous_certificate_rotation()
    {
        var assets = CreateDataProtectionAssets();
        try
        {
            using var previousCertificate = X509CertificateLoader.LoadPkcs12FromFile(
                assets.CertificatePath, assets.Password, X509KeyStorageFlags.EphemeralKeySet);
            using var currentCertificate = CreateEncryptionCertificate();
            const string purpose = "SentinelAI.Web.AuthenticationCookie";
            const string value = "tenant-scoped-authentication-ticket";

            string protectedPayload;
            var oldReplicaServices = new ServiceCollection();
            {
                oldReplicaServices.AddDataProtection()
                    .SetApplicationName("SentinelAI.Web")
                    .PersistKeysToFileSystem(new DirectoryInfo(assets.KeyRingDirectory))
                    .ProtectKeysWithCertificate(previousCertificate);
                using var oldReplicaProvider = oldReplicaServices.BuildServiceProvider();
                protectedPayload = oldReplicaProvider.GetRequiredService<IDataProtectionProvider>()
                    .CreateProtector(purpose).Protect(value);
            }

            var replacementReplicaServices = new ServiceCollection();
            replacementReplicaServices.AddDataProtection()
                .SetApplicationName("SentinelAI.Web")
                .PersistKeysToFileSystem(new DirectoryInfo(assets.KeyRingDirectory))
                .ProtectKeysWithCertificate(currentCertificate)
                .UnprotectKeysWithAnyCertificate(currentCertificate, previousCertificate);
            using var replacementReplicaProvider = replacementReplicaServices.BuildServiceProvider();

            var roundTrip = replacementReplicaProvider.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector(purpose).Unprotect(protectedPayload);

            Assert.Equal(value, roundTrip);
        }
        finally
        {
            assets.Dispose();
        }
    }

    [Fact]
    public void Production_rejects_unavailable_or_non_persistent_key_ring_directory()
    {
        var assets = CreateDataProtectionAssets();
        try
        {
            var configuration = CreateConfiguration(
                Path.Combine(assets.RootDirectory, "missing-shared-key-ring"),
                assets.CertificatePath,
                assets.Password);

            var exception = Assert.Throws<InvalidOperationException>(() =>
                WebProductionConfigurationValidator.Validate(configuration, new TestEnvironment()));

            Assert.Contains("DataProtection:KeyRingPath", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            assets.Dispose();
        }
    }

    [Fact]
    public void Production_rejects_encryption_certificate_without_private_key()
    {
        var assets = CreateDataProtectionAssets(exportPrivateKey: false);
        try
        {
            var configuration = CreateConfiguration(assets.KeyRingDirectory, assets.CertificatePath, assets.Password);

            var exception = Assert.Throws<InvalidOperationException>(() =>
                WebProductionConfigurationValidator.Validate(configuration, new TestEnvironment()));

            Assert.Contains("private key", exception.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            assets.Dispose();
        }
    }

    private static IConfiguration CreateConfiguration(string keyRingPath, string certificatePath, string password)
        => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Authentication:Authority"] = "https://identity.example.com/",
            ["Authentication:ClientId"] = "sentinelai-web",
            ["Authentication:ClientSecret"] = "oidc-client-secret-from-secret-store",
            ["Api:BaseUrl"] = "https://api.sentinelai.example.com",
            ["Security:RequireHttps"] = "true",
            ["ReverseProxy:KnownProxies:0"] = "10.0.0.10",
            ["AllowedHosts"] = "sentinelai.example.com",
            ["DataProtection:KeyRingPath"] = keyRingPath,
            ["DataProtection:CertificatePath"] = certificatePath,
            ["DataProtection:CertificatePassword"] = password
        }).Build();

    private static X509Certificate2 CreateEncryptionCertificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=SentinelAI Current Data Protection",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment, true));
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddDays(30));
    }

    private static DataProtectionTestAssets CreateDataProtectionAssets(bool exportPrivateKey = true)
    {
        const string password = "test-data-protection-secret";
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-dp-{Guid.NewGuid():N}");
        var keyRing = Path.Combine(root, "shared-key-ring");
        Directory.CreateDirectory(keyRing);

        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=SentinelAI Test Data Protection",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment, true));
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddDays(30));

        var path = Path.Combine(root, "data-protection.pfx");
        byte[] certificateBytes;
        if (exportPrivateKey)
        {
            certificateBytes = certificate.Export(X509ContentType.Pfx, password);
        }
        else
        {
            using var publicOnlyCertificate = X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));
            certificateBytes = publicOnlyCertificate.Export(X509ContentType.Pfx, password);
        }
        File.WriteAllBytes(path, certificateBytes);
        return new DataProtectionTestAssets(root, keyRing, path, password);
    }

    private sealed class DataProtectionTestAssets(
        string rootDirectory,
        string keyRingDirectory,
        string certificatePath,
        string password) : IDisposable
    {
        public string RootDirectory { get; } = rootDirectory;
        public string KeyRingDirectory { get; } = keyRingDirectory;
        public string CertificatePath { get; } = certificatePath;
        public string Password { get; } = password;

        public void Dispose()
        {
            if (Directory.Exists(RootDirectory))
                Directory.Delete(RootDirectory, recursive: true);
        }
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Production";
        public string ApplicationName { get; set; } = "SentinelAI.UnitTests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
