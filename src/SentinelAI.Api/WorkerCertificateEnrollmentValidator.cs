using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SentinelAI.Api;

public static class WorkerCertificateEnrollmentValidator
{
    public const string ClientAuthenticationEku = "1.3.6.1.5.5.7.3.2";
    private static readonly TimeSpan MaximumCertificateLifetime = TimeSpan.FromDays(90);

    public static X509Certificate2 Validate(
        string certificatePem,
        IReadOnlyCollection<string>? intermediateCertificatesPem,
        string workerIdentity,
        string trustedRootCertificatePath,
        DateTimeOffset? now = null)
    {
        if (string.IsNullOrWhiteSpace(certificatePem) || certificatePem.Length > 64 * 1024)
            throw new ArgumentException("A bounded PEM-encoded public client certificate is required.", nameof(certificatePem));
        if (string.IsNullOrWhiteSpace(workerIdentity))
            throw new ArgumentException("A provisioned worker identity is required.", nameof(workerIdentity));
        if (string.IsNullOrWhiteSpace(trustedRootCertificatePath) || !File.Exists(trustedRootCertificatePath))
            throw new InvalidOperationException("The trusted worker CA certificate is not mounted.");

        if (certificatePem.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Private keys must never be uploaded to the control plane.", nameof(certificatePem));

        var certificate = X509Certificate2.CreateFromPem(certificatePem);
        try
        {
            if (certificate.HasPrivateKey)
                throw new ArgumentException("Private keys must never be uploaded to the control plane.", nameof(certificatePem));

            var expectedName = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            if (!string.Equals(expectedName, workerIdentity, StringComparison.Ordinal))
                throw new ArgumentException("The certificate subject must match the administrator-selected worker identity.", nameof(certificatePem));

            var moment = (now ?? DateTimeOffset.UtcNow).ToUniversalTime();
            var notBefore = new DateTimeOffset(certificate.NotBefore.ToUniversalTime());
            var notAfter = new DateTimeOffset(certificate.NotAfter.ToUniversalTime());
            if (notBefore > moment.AddMinutes(1) || notAfter <= moment)
                throw new ArgumentException("The worker certificate is not currently valid.", nameof(certificatePem));
            if (notAfter - notBefore > MaximumCertificateLifetime)
                throw new ArgumentException("Worker client certificates must have a lifetime of 90 days or less.", nameof(certificatePem));

            var basicConstraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
            if (basicConstraints is null || basicConstraints.CertificateAuthority)
                throw new ArgumentException("A worker certificate must be an end-entity client certificate.", nameof(certificatePem));

            var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
            if (eku is null || !eku.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == ClientAuthenticationEku))
                throw new ArgumentException("A worker certificate must include the TLS client-authentication EKU.", nameof(certificatePem));

            var keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
            if (keyUsage is not null && !keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature))
                throw new ArgumentException("A worker certificate must permit digital signatures.", nameof(certificatePem));

            using var root = X509CertificateLoader.LoadCertificateFromFile(trustedRootCertificatePath);
            var rootConstraints = root.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
            if (rootConstraints is null || !rootConstraints.CertificateAuthority)
                throw new InvalidOperationException("The configured worker trust anchor is not a CA certificate.");

            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(root);
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ClientAuthenticationEku));
            chain.ChainPolicy.VerificationTime = moment.UtcDateTime;
            // Revocation is checked against the authoritative binding row on every authentication.
            // Do not make worker availability depend on an external CRL/OCSP service.
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            foreach (var intermediatePem in intermediateCertificatesPem ?? [])
            {
                if (string.IsNullOrWhiteSpace(intermediatePem) || intermediatePem.Length > 64 * 1024)
                    throw new ArgumentException("An intermediate certificate PEM is invalid.", nameof(intermediateCertificatesPem));
                if (intermediatePem.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Private keys must never be uploaded to the control plane.", nameof(intermediateCertificatesPem));
                using var intermediate = X509Certificate2.CreateFromPem(intermediatePem);
                if (intermediate.HasPrivateKey)
                    throw new ArgumentException("Private keys must never be uploaded to the control plane.", nameof(intermediateCertificatesPem));
                chain.ChainPolicy.ExtraStore.Add(intermediate);
            }

            if (!chain.Build(certificate))
                throw new ArgumentException("The worker certificate does not chain to the configured trusted CA for client authentication.", nameof(certificatePem));

            return certificate;
        }
        catch
        {
            certificate.Dispose();
            throw;
        }
    }
}
