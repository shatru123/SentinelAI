using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SentinelAI.AI.Abstractions;
using SentinelAI.Application;
using SentinelAI.Contracts;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;

namespace SentinelAI.UnitTests;

public sealed class FindingAIAnalysisServiceTests
{
    [Fact]
    public async Task Analysis_persists_provenance_and_does_not_change_the_finding()
    {
        await using var db = CreateDb();
        var seed = await SeedAsync(db);
        var provider = new FakeProvider("test", BuildResult(seed.Evidence.Id));
        var service = new FindingAIAnalysisService(db, new AIProviderFactory([provider]));
        var response = await service.AnalyzeAsync(seed.Principal, seed.Finding.Id, new AnalyzeFindingRequest("TEST"));

        Assert.Equal("test", response.Provider);
        Assert.Equal("finding-analysis-v1", response.PromptTemplateVersion);
        Assert.Equal(64, response.EvidenceSha256.Length);
        Assert.Equal(seed.Evidence.Id, Assert.Single(response.Result.RecommendedActions).EvidenceIds.Single());
        var saved = await db.FindingAIAnalyses.SingleAsync();
        Assert.Equal(seed.Principal.UserId, saved.ActorId);
        Assert.Equal(response.EvidenceSha256, saved.EvidenceSha256);
        Assert.Single(await db.AuditEvents.Where(x => x.Action == "ai.finding-analysis.created").ToListAsync());
        Assert.Equal(FindingSeverity.Medium, (await db.Findings.SingleAsync(x => x.Id == seed.Finding.Id)).Severity);
    }

    [Fact]
    public async Task Analysis_rejects_evidence_identifiers_not_supplied_to_the_provider()
    {
        await using var db = CreateDb();
        var seed = await SeedAsync(db);
        var service = new FindingAIAnalysisService(db, new AIProviderFactory([new FakeProvider("test", BuildResult(Guid.NewGuid()))]));
        var ex = await Assert.ThrowsAsync<AIProviderUnavailableException>(() =>
            service.AnalyzeAsync(seed.Principal, seed.Finding.Id, new AnalyzeFindingRequest("test")));
        Assert.Contains("evidence", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(await db.FindingAIAnalyses.ToListAsync());
    }

    [Fact]
    public async Task Viewer_cannot_request_analysis()
    {
        await using var db = CreateDb();
        var seed = await SeedAsync(db);
        var provider = new FakeProvider("test", BuildResult(seed.Evidence.Id));
        var service = new FindingAIAnalysisService(db, new AIProviderFactory([provider]));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            service.AnalyzeAsync(seed.Principal with { Role = UserRole.Viewer }, seed.Finding.Id, new AnalyzeFindingRequest("test")));
        Assert.Equal(0, provider.CallCount);
    }

    [Fact]
    public async Task Finding_analysis_is_tenant_scoped()
    {
        await using var db = CreateDb();
        var seed = await SeedAsync(db);
        var tenant = new Tenant("Other tenant");
        var user = new User(tenant.Id, "other", "Other", UserRole.Admin);
        db.AddRange(tenant, user);
        await db.SaveChangesAsync();
        var provider = new FakeProvider("test", BuildResult(seed.Evidence.Id));
        var service = new FindingAIAnalysisService(db, new AIProviderFactory([provider]));
        var other = new PrincipalContext(tenant.Id, user.Id, user.Subject, user.Role);
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            service.AnalyzeAsync(other, seed.Finding.Id, new AnalyzeFindingRequest("test")));
        Assert.Equal(0, provider.CallCount);
        Assert.Null(await service.ListAsync(other, seed.Finding.Id));
    }

    [Fact]
    public async Task Unconfigured_provider_is_rejected_without_calling_it()
    {
        await using var db = CreateDb();
        var seed = await SeedAsync(db);
        var provider = new FakeProvider("test", BuildResult(seed.Evidence.Id), configured: false);
        var service = new FindingAIAnalysisService(db, new AIProviderFactory([provider]));
        await Assert.ThrowsAsync<AIProviderUnavailableException>(() =>
            service.AnalyzeAsync(seed.Principal, seed.Finding.Id, new AnalyzeFindingRequest("test")));
        Assert.Equal(0, provider.CallCount);
    }

    [Fact]
    public async Task Analysis_history_can_be_read_by_tenant()
    {
        await using var db = CreateDb();
        var seed = await SeedAsync(db);
        var service = new FindingAIAnalysisService(db, new AIProviderFactory([new FakeProvider("test", BuildResult(seed.Evidence.Id))]));
        await service.AnalyzeAsync(seed.Principal, seed.Finding.Id, new AnalyzeFindingRequest("test"));
        var history = await service.ListAsync(seed.Principal, seed.Finding.Id);
        Assert.NotNull(history);
        Assert.Single(history);
    }

    [Fact]
    public async Task Finding_without_evidence_cannot_be_analyzed()
    {
        await using var db = CreateDb();
        var seed = await SeedAsync(db, includeEvidence: false);
        var provider = new FakeProvider("test", BuildResult(Guid.NewGuid()));
        var service = new FindingAIAnalysisService(db, new AIProviderFactory([provider]));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.AnalyzeAsync(seed.Principal, seed.Finding.Id, new AnalyzeFindingRequest("test")));
        Assert.Equal(0, provider.CallCount);
    }

    private static AppDbContext CreateDb()
        => new(new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);

    private static async Task<SeedData> SeedAsync(AppDbContext db, bool includeEvidence = true)
    {
        var tenant = new Tenant("Analysis tenant");
        var user = new User(tenant.Id, "analyst", "Analyst", UserRole.SecurityAnalyst);
        var finding = new Finding(tenant.Id, null, "Missing security header", FindingSeverity.Medium);
        finding.ConfigureAssessmentDetails(Guid.NewGuid(), "SecurityHeaders", "High", "https://example.test/", "GET", null,
            "Strict transport security header was not observed.", "Transport downgrade protection may be reduced.", null,
            "Configure Strict-Transport-Security after validating HTTPS coverage.", null, WebCheckStatus.FindingDetected);
        var evidence = new Evidence(tenant.Id, finding.Id, "http-response", "Response headers did not contain HSTS.", new string('a', 64));
        evidence.ConfigureContent("HTTP/1.1 200 OK\nX-Content-Type-Options: nosniff", "text/plain");
        db.AddRange(tenant, user, finding);
        if (includeEvidence) db.Evidence.Add(evidence);
        await db.SaveChangesAsync();
        return new SeedData(finding, evidence, new PrincipalContext(tenant.Id, user.Id, user.Subject, user.Role));
    }

    private static string BuildResult(Guid evidenceId)
        => JsonSerializer.Serialize(new FindingAIAnalysisResultResponse(
            "The response omitted the HSTS header.",
            "Clients may be more exposed to protocol downgrade attempts.",
            "Medium",
            [new FindingAIRecommendationResponse("Review HTTPS coverage and add a suitable HSTS policy.",
                "The attached response-header evidence does not show the HSTS header.", [evidenceId])],
            ["The assessment did not verify browser-side behavior."]));

    private sealed record SeedData(Finding Finding, Evidence Evidence, PrincipalContext Principal);

    private sealed class FakeProvider(string name, string content, bool configured = true) : IAIProvider
    {
        public string Name => name;
        public bool IsConfigured => configured;
        public int CallCount { get; private set; }
        public Task<AIResponse> AnalyzeAsync(AIRequest request, CancellationToken cancellationToken = default)
        {
            CallCount++;
            Assert.Contains("untrusted data", request.SystemPrompt, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("evidence", request.UserPrompt, StringComparison.OrdinalIgnoreCase);
            Assert.NotNull(request.JsonSchemaJson);
            return Task.FromResult(new AIResponse(Name, "test-model", content, 20, 10, "response-1", "stop", true));
        }
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(configured);
    }
}
