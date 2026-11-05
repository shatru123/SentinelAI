using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

namespace SentinelAI.UnitTests;

public sealed class SharedWebDataProtectionTests
{
    [Fact]
    public void Shared_key_ring_is_readable_by_another_web_replica_and_supports_certificate_overlap()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-shared-dp-{Guid.NewGuid():N}");
        var keyRing = Path.Combine(root, "shared-key-ring");
        Directory.CreateDirectory(keyRing);

        using var originalCertificate = CreateCertificate("SentinelAI DP original");
        using var replacementCertificate = CreateCertificate("SentinelAI DP replacement");
        try
        {
            string payloadFromOriginalReplica;
            using (var originalReplica = CreateReplica(keyRing, originalCertificate, originalCertificate))
            {
                var protector = originalReplica.GetRequiredService<IDataProtectionProvider>()
                    .CreateProtector("SentinelAI.Web.IntegrationCookie");
                payloadFromOriginalReplica = protector.Protect("authenticated-session-original");
            }

            string payloadFromReplacementReplica;
            using (var replacementReplica = CreateReplica(
                keyRing,
                replacementCertificate,
                replacementCertificate,
                originalCertificate))
            {
                var protector = replacementReplica.GetRequiredService<IDataProtectionProvider>()
                    .CreateProtector("SentinelAI.Web.IntegrationCookie");

                Assert.Equal("authenticated-session-original", protector.Unprotect(payloadFromOriginalReplica));
                payloadFromReplacementReplica = protector.Protect("authenticated-session-replacement");
            }

            // A newly started pod using the replacement certificate must be able to
            // read both the old persisted key and newly created keys during overlap.
            using (var anotherReplacementReplica = CreateReplica(
                keyRing,
                replacementCertificate,
                replacementCertificate,
                originalCertificate))
            {
                var protector = anotherReplacementReplica.GetRequiredService<IDataProtectionProvider>()
                    .CreateProtector("SentinelAI.Web.IntegrationCookie");

                Assert.Equal("authenticated-session-original", protector.Unprotect(payloadFromOriginalReplica));
                Assert.Equal("authenticated-session-replacement", protector.Unprotect(payloadFromReplacementReplica));
            }

            Assert.NotEmpty(Directory.EnumerateFiles(keyRing, "*.xml"));
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }

    private static ServiceProvider CreateReplica(
        string keyRingPath,
        X509Certificate2 currentCertificate,
        params X509Certificate2[] certificatesForDecryption)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection()
            .SetApplicationName("SentinelAI.Web")
            .PersistKeysToFileSystem(new DirectoryInfo(keyRingPath))
            .ProtectKeysWithCertificate(currentCertificate)
            .UnprotectKeysWithAnyCertificate(certificatesForDecryption);

        return services.BuildServiceProvider();
    }

    private static X509Certificate2 CreateCertificate(string commonName)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={commonName}",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment,
            critical: true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(30));
    }
}
