using System.Text;
using Microsoft.EntityFrameworkCore;
using SentinelAI.Agent.Vulnerability;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;

namespace SentinelAI.UnitTests;

public sealed class WebAssessmentReportTests
{
    [Fact]
    public async Task Html_report_escapes_target_content_and_embeds_screenshot_bytes()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        await using var db = new AppDbContext(options);
        var tenant = new Tenant("Report tenant");
        var scope = new TargetScope(tenant.Id, "scope", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Web, "https://example.test")], [], ["web-assessment-passive"], 10, 120, "approved", false);
        var job = new AgentJob(tenant.Id, scope.Id, Guid.NewGuid(), "web-assessment-passive");
        var assessment = new WebAssessment(tenant.Id, job.Id, scope.Id, "https://report-user:report-password@example.test/<unsafe>?access_token=never-report-this&view=login#secret-fragment", "web-assessment-passive", WebHostingMode.Public);
        var finding = new Finding(tenant.Id, null, "<script>alert(1)</script>", FindingSeverity.Low);
        finding.ConfigureAssessmentDetails(assessment.Id, "headers", "High", assessment.TargetUrl, "GET", null, "<unsafe>", "impact", "safe", "fix", "ref", WebCheckStatus.Confirmed);
        var evidence = new Evidence(tenant.Id, finding.Id, "test", "evidence", "hash");
        evidence.ConfigureContent("<script>no</script>", "text/plain");
        var screenshot = new AssessmentScreenshot(tenant.Id, assessment.Id, finding.Id, assessment.TargetUrl, "landing", "image/png", "tenant/assessment/shot.png", "hash");
        var credentialBoundary = new WebAssessmentCheck(tenant.Id, assessment.Id, "credentials.no-submission",
            "Credential submission boundary", "Authentication safety", WebCheckStatus.Informational, assessment.TargetUrl);
        credentialBoundary.Complete(WebCheckStatus.Informational,
            "No password, API key, bearer token, or session-cookie value was submitted or retained.");
        db.AddRange(tenant, scope, job, assessment, finding, evidence, screenshot, credentialBoundary);
        await db.SaveChangesAsync();
        var store = new FakeStore { Bytes = [137, 80, 78, 71] };
        var report = await new HtmlReportGenerator(db, store).GenerateAsync(tenant.Id, assessment, scope, CancellationToken.None);
        var html = await store.GetTextAsync(store.LastKey!);

        Assert.Contains("data:image/png;base64,", html);
        Assert.DoesNotContain("<script>alert(1)</script>", html);
        Assert.Contains("&lt;script&gt;alert(1)&lt;/script&gt;", html);
        Assert.Contains("&lt;unsafe&gt;", html);
        Assert.Contains("access_token=REDACTED", html);
        Assert.Contains("view=login", html);
        Assert.DoesNotContain("never-report-this", html);
        Assert.DoesNotContain("report-user", html);
        Assert.DoesNotContain("report-password", html);
        Assert.DoesNotContain("secret-fragment", html);
        Assert.Contains("Authentication and credential handling", html);
        Assert.Contains("Credentials attempted:</strong> 0", html);
        Assert.Contains("Credential values stored in this report:</strong> None", html);
        Assert.Contains("Credential submission boundary", html);
        Assert.Contains("No password, API key, bearer token, or session-cookie value was submitted or retained.", html);
    }

    [Fact]
    public async Task Persisted_ai_advisory_summary_is_opt_in_and_html_encoded()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        await using var db = new AppDbContext(options);
        var tenant = new Tenant("AI report tenant");
        var scope = new TargetScope(tenant.Id, "scope", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Web, "https://example.test")], [], ["web-assessment-passive"], 10, 120, "approved", false);
        var job = new AgentJob(tenant.Id, scope.Id, Guid.NewGuid(), "web-assessment-passive");
        var assessment = new WebAssessment(tenant.Id, job.Id, scope.Id, "https://example.test", "web-assessment-passive", WebHostingMode.Public);
        var finding = new Finding(tenant.Id, null, "Missing security header", FindingSeverity.Medium);
        finding.ConfigureAssessmentDetails(assessment.Id, "headers", "Medium", assessment.TargetUrl, "GET", null, "HSTS is missing", "Transport protection may be reduced", "Review HTTPS", "Configure HSTS", "evidence-1", WebCheckStatus.Confirmed);
        var evidence = new Evidence(tenant.Id, finding.Id, "test", "redacted summary", new string('b', 64));
        var analysis = new FindingAIAnalysis(
            tenant.Id, finding.Id, Guid.NewGuid(), "test-provider", "test-model",
            "finding-analysis-v1", new string('a', 64), "<script>persisted advisory</script>",
            "{\"summary\":\"persisted\"}", 12, 8, "response-1", "stop");
        db.AddRange(tenant, scope, job, assessment, finding, evidence, analysis);
        await db.SaveChangesAsync();
        var store = new FakeStore();
        var generator = new HtmlReportGenerator(db, store);

        var defaultKey = await generator.GenerateAsync(tenant.Id, assessment, scope, CancellationToken.None);
        var defaultHtml = await store.GetTextAsync(defaultKey);
        Assert.DoesNotContain("persisted advisory", defaultHtml);

        var advisoryKey = await generator.GenerateAsync(tenant.Id, assessment, scope, CancellationToken.None, includeAdvisoryAiSummaries: true);
        var advisoryHtml = await store.GetTextAsync(advisoryKey);
        Assert.Contains("AI advisory summary", advisoryHtml);
        Assert.Contains("Provider: test-provider", advisoryHtml);
        Assert.Contains("Evidence SHA-256:", advisoryHtml);
        Assert.Contains("&lt;script&gt;persisted advisory&lt;/script&gt;", advisoryHtml);
        Assert.DoesNotContain("<script>persisted advisory</script>", advisoryHtml);
    }

    private sealed class FakeStore : IAssessmentArtifactStore
    {
        private readonly Dictionary<string, byte[]> files = [];
        public byte[] Bytes { get; set; } = [];
        public string? LastKey { get; private set; }
        public Task<string> PutAsync(Guid tenantId, Guid assessmentId, string name, byte[] content, CancellationToken cancellationToken)
        { LastKey = $"{tenantId}/{assessmentId}/{name}"; files[LastKey] = content; return Task.FromResult(LastKey); }
        public Task<byte[]?> GetAsync(Guid tenantId, string storageKey, CancellationToken cancellationToken) => Task.FromResult(files.TryGetValue(storageKey, out var value) ? (byte[]?)value : storageKey.EndsWith("shot.png", StringComparison.Ordinal) ? Bytes : null);
        public Task<string> StageReportAsync(Guid tenantId, Guid assessmentId, byte[] content, CancellationToken cancellationToken)
        { LastKey = $"{tenantId}/{assessmentId}/.staging/report.html"; files[LastKey] = content; return Task.FromResult(LastKey); }
        public Task<string> PublishReportAsync(Guid tenantId, Guid assessmentId, string stagingKey, CancellationToken cancellationToken)
        { var key = $"{tenantId}/{assessmentId}/reports/report.html"; files[key] = files[stagingKey]; files.Remove(stagingKey); return Task.FromResult(key); }
        public Task<byte[]?> GetPublishedReportAsync(Guid tenantId, Guid assessmentId, string storageKey, CancellationToken cancellationToken)
            => Task.FromResult(files.TryGetValue(storageKey, out var value) ? (byte[]?)value : null);
        public Task DiscardReportAsync(Guid tenantId, Guid assessmentId, string storageKey, CancellationToken cancellationToken)
        { files.Remove(storageKey); return Task.CompletedTask; }
        public Task<int> CleanupStagedReportsAsync(DateTimeOffset olderThan, CancellationToken cancellationToken) => Task.FromResult(0);
        public Task<int> ReconcilePublishedReportsAsync(DateTimeOffset olderThan, Func<string, Task<bool>> isReferencedAsync, CancellationToken cancellationToken) => Task.FromResult(0);
        public Task<string> GetTextAsync(string key) => Task.FromResult(Encoding.UTF8.GetString(files[key]));
    }
}
