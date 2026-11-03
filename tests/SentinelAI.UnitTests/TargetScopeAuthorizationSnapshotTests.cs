using SentinelAI.Domain;

namespace SentinelAI.UnitTests;

public sealed class TargetScopeAuthorizationSnapshotTests
{
    [Theory]
    [InlineData("allow-subdomains")]
    [InlineData("target")]
    [InlineData("remove-exclusion")]
    [InlineData("add-exclusion")]
    [InlineData("remove-profile")]
    [InlineData("verification-expiry")]
    [InlineData("max-total-requests")]
    [InlineData("requests-per-minute")]
    [InlineData("max-pages")]
    [InlineData("crawl-depth")]
    [InlineData("response-bytes")]
    [InlineData("execution-seconds")]
    [InlineData("private-worker")]
    [InlineData("private-ranges")]
    public void Authorization_fingerprint_changes_for_every_execution_relevant_scope_mutation(string mutation)
    {
        var scope = CreateScope();
        var original = scope.GetAuthorizationFingerprint();

        switch (mutation)
        {
            case "allow-subdomains":
                Reconfigure(scope, allowSubdomains: true);
                break;
            case "target":
                Reconfigure(scope, targets: [new TargetDefinition(TargetKind.Web, "https://other.example/app")]);
                break;
            case "remove-exclusion":
                Reconfigure(scope, exclusions: []);
                break;
            case "add-exclusion":
                Reconfigure(scope, exclusions: ["https://example.com/admin"]);
                break;
            case "remove-profile":
                Reconfigure(scope, profiles: ["web-assessment-passive"]);
                break;
            case "verification-expiry":
                scope.ConfigureVerifications([new PublicTargetVerification("https://example.com/app", "ticket", "verifier", "registry", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(-1))]);
                break;
            case "max-total-requests":
                Reconfigure(scope, maxTotalRequests: 99);
                break;
            case "requests-per-minute":
                Reconfigure(scope, requestsPerMinute: 25);
                break;
            case "max-pages":
                Reconfigure(scope, maxPages: 23);
                break;
            case "crawl-depth":
                Reconfigure(scope, maxCrawlDepth: 3);
                break;
            case "response-bytes":
                Reconfigure(scope, maxResponseBytes: 512 * 1024 + 1);
                break;
            case "execution-seconds":
                Reconfigure(scope, maxExecutionSeconds: 121);
                break;
            case "private-worker":
                scope.ConfigureWebHosting(WebHostingMode.Private, "worker-b", ["10.0.0.0/8"]);
                break;
            case "private-ranges":
                scope.ConfigureWebHosting(WebHostingMode.Private, "worker-a", ["10.1.0.0/16"]);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mutation), mutation, null);
        }

        Assert.NotEqual(original, scope.GetAuthorizationFingerprint());
    }

    private static TargetScope CreateScope()
    {
        var tenant = Guid.NewGuid();
        var scope = new TargetScope(tenant, "snapshot", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure(
            [new TargetDefinition(TargetKind.Web, "https://example.com/app")],
            ["https://example.com/private"],
            ["web-assessment-passive", "web-assessment-safe-active"],
            requestsPerMinute: 30,
            maxExecutionSeconds: 120,
            authorizationEvidence: "ticket",
            publicTargetOwnershipVerified: false,
            allowSubdomains: false,
            maxTotalRequests: 100,
            maxConcurrentRequests: 4,
            maxPages: 24,
            maxCrawlDepth: 2,
            maxResponseBytes: 512 * 1024);
        scope.ConfigureVerifications([new PublicTargetVerification("https://example.com/app", "ticket", "verifier", "registry", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1))]);
        scope.ConfigureWebHosting(WebHostingMode.Public);
        return scope;
    }

    private static void Reconfigure(
        TargetScope scope,
        IReadOnlyCollection<TargetDefinition>? targets = null,
        IReadOnlyCollection<string>? exclusions = null,
        IReadOnlyCollection<string>? profiles = null,
        int? requestsPerMinute = null,
        int? maxExecutionSeconds = null,
        bool? allowSubdomains = null,
        int? maxTotalRequests = null,
        int? maxPages = null,
        int? maxCrawlDepth = null,
        int? maxResponseBytes = null)
    {
        scope.Configure(
            targets ?? scope.Targets,
            exclusions ?? scope.Exclusions,
            profiles ?? scope.ApprovedOperationProfiles,
            requestsPerMinute ?? scope.RequestsPerMinute,
            maxExecutionSeconds ?? scope.MaxExecutionSeconds,
            scope.AuthorizationEvidence,
            publicTargetOwnershipVerified: false,
            allowSubdomains ?? scope.AllowSubdomains,
            maxTotalRequests ?? scope.MaxTotalRequests,
            scope.MaxConcurrentRequests,
            maxPages ?? scope.MaxPages,
            maxCrawlDepth ?? scope.MaxCrawlDepth,
            maxResponseBytes ?? scope.MaxResponseBytes);
    }
}
