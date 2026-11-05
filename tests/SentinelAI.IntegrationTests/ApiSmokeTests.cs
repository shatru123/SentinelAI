using System.Net;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Net.Http.Json;
using System.Text.Json;
using SentinelAI.AI.Abstractions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Contracts;
using SentinelAI.Agent.Vulnerability;
using SentinelAI.Application;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;
using SentinelAI.Security.Policy;

namespace SentinelAI.IntegrationTests;

public sealed class ApiSmokeTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> factory;
    private readonly Guid tenantId = Guid.NewGuid();
    private readonly Guid userId = Guid.NewGuid();

    public ApiSmokeTests(WebApplicationFactory<Program> factory)
    {
        this.factory = factory.WithWebHostBuilder(builder => builder.UseEnvironment("Development").UseSetting("Database:Provider", "InMemory"));
    }

    [Fact]
    public async Task Health_is_public_and_scope_creation_requires_authentication()
    {
        using var client = factory.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/scopes")).StatusCode);
    }

    [Fact]
    public async Task AI_provider_status_is_authenticated_and_does_not_call_unconfigured_providers()
    {
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/v1/ai/providers")).StatusCode);

        using var reader = CreateAuthenticatedClient(tenantId, userId, UserRole.Viewer);
        var response = await reader.GetAsync("/api/v1/ai/providers");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var providers = document.RootElement.GetProperty("providers").EnumerateArray().ToArray();
        Assert.Equal(3, providers.Length);
        Assert.All(providers, provider =>
        {
            Assert.False(provider.GetProperty("configured").GetBoolean());
            Assert.False(provider.GetProperty("healthy").GetBoolean());
        });
    }

    [Fact]
    public async Task AI_provider_status_supports_legacy_environment_configuration()
    {
        using var legacyFactory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["OPENAI_API_KEY"] = "legacy-test-key",
                    ["OPENAI_MODEL"] = "gpt-test",
                    ["AI:DefaultProvider"] = "openai"
                }));

            builder.ConfigureTestServices(services =>
                services.AddHttpClient("sentinelai-ai-openai")
                    .ConfigurePrimaryHttpMessageHandler(() => new ProviderHealthHandler()));
        });

        using var client = CreateAuthenticatedClient(legacyFactory, tenantId, userId, UserRole.Viewer);
        var response = await client.GetAsync("/api/v1/ai/providers");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("openai", document.RootElement.GetProperty("selectedProvider").GetString());
        Assert.True(document.RootElement.GetProperty("openAiCredentialsConfigured").GetBoolean());
        Assert.True(document.RootElement.GetProperty("openAiHealthy").GetBoolean());
        Assert.True(document.RootElement.GetProperty("connectivityVerified").GetBoolean());
    }

    [Fact]
    public async Task Authenticated_operator_can_register_bounded_scope()
    {
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Tenant-Id", tenantId.ToString());
        client.DefaultRequestHeaders.Add("X-User-Id", userId.ToString());
        client.DefaultRequestHeaders.Add("X-Role", "SecurityAnalyst");
        var request = new CreateScopeRequest("integration-lab", [new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], ["mock-passive"], 30, 300, "ticket-integration-1", DateTimeOffset.UtcNow.AddHours(1));

        var response = await client.PostAsJsonAsync("/api/v1/scopes", request);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var scope = await response.Content.ReadFromJsonAsync<ScopeResponse>();
        Assert.NotNull(scope);
        Assert.Equal(tenantId, scope.TenantId);
    }

    [Fact]
    public async Task Tenant_isolation_is_enforced_by_actual_api_queries()
    {
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Tenant-Id", tenantId.ToString());
        client.DefaultRequestHeaders.Add("X-User-Id", userId.ToString());
        client.DefaultRequestHeaders.Add("X-Role", "SecurityAnalyst");
        var create = new CreateScopeRequest("tenant-a", [new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], ["mock-passive"], 30, 300, "ticket-a", DateTimeOffset.UtcNow.AddHours(1));
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsJsonAsync("/api/v1/scopes", create)).StatusCode);
        client.DefaultRequestHeaders.Remove("X-Tenant-Id"); client.DefaultRequestHeaders.Add("X-Tenant-Id", Guid.NewGuid().ToString());
        var response = await client.GetFromJsonAsync<PagedResponse<ScopeResponse>>("/api/v1/scopes");
        Assert.NotNull(response);
        Assert.Equal(0, response.TotalCount);
    }

    [Fact]
    public async Task Caller_boolean_cannot_authorize_a_public_target()
    {
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Tenant-Id", Guid.NewGuid().ToString());
        client.DefaultRequestHeaders.Add("X-User-Id", Guid.NewGuid().ToString());
        client.DefaultRequestHeaders.Add("X-Role", "SecurityAnalyst");
        var request = new CreateScopeRequest("public", [new TargetDefinition(TargetKind.Network, "8.8.8.8")], [], ["mock-passive"], 30, 300, "ticket-public", DateTimeOffset.UtcNow.AddHours(1), true);
        var response = await client.PostAsJsonAsync("/api/v1/scopes", request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Public_target_requires_separate_administrator_approval()
    {
        using var client = factory.CreateClient();
        var requester = Guid.NewGuid();
        client.DefaultRequestHeaders.Add("X-Tenant-Id", tenantId.ToString());
        client.DefaultRequestHeaders.Add("X-User-Id", requester.ToString());
        client.DefaultRequestHeaders.Add("X-Role", "SecurityAnalyst");
        var requested = await client.PostAsJsonAsync("/api/v1/public-target-authorizations", new PublicTargetAuthorizationRequest("https://example.com", "Approved lab engagement"));
        Assert.Equal(HttpStatusCode.Created, requested.StatusCode);
        var authorization = await requested.Content.ReadFromJsonAsync<PublicTargetAuthorizationResponse>();
        Assert.NotNull(authorization);

        client.DefaultRequestHeaders.Remove("X-User-Id");
        client.DefaultRequestHeaders.Add("X-User-Id", Guid.NewGuid().ToString());
        client.DefaultRequestHeaders.Remove("X-Role");
        client.DefaultRequestHeaders.Add("X-Role", "Admin");
        var approved = await client.PostAsJsonAsync($"/api/v1/public-target-authorizations/{authorization!.Id}/approve", new PublicTargetAuthorizationApprovalRequest("ticket-123", "security-review", DateTimeOffset.UtcNow.AddHours(1)));
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);

        var listed = await client.GetFromJsonAsync<List<PublicTargetAuthorizationResponse>>("/api/v1/public-target-authorizations");
        Assert.NotNull(listed);
        Assert.Contains(listed, item => item.Id == authorization.Id && item.Status == PublicTargetAuthorizationStatus.Approved);

        var scope = new CreateScopeRequest("approved-public", [new TargetDefinition(TargetKind.Web, "https://example.com")], [], ["web-passive"], 30, 300, "ticket-123", DateTimeOffset.UtcNow.AddHours(1), false, null, [authorization.Id]);
        var createdScope = await client.PostAsJsonAsync("/api/v1/scopes", scope);
        Assert.Equal(HttpStatusCode.Created, createdScope.StatusCode);
    }

    [Fact]
    public async Task Scheduled_reassessment_requires_existing_approved_scope_and_operator_role()
    {
        var analystId = Guid.NewGuid();
        using var analyst = CreateAuthenticatedClient(tenantId, analystId, UserRole.SecurityAnalyst);
        var requested = await analyst.PostAsJsonAsync("/api/v1/public-target-authorizations",
            new PublicTargetAuthorizationRequest("https://example.com", "Approved recurring assessment integration test"));
        Assert.Equal(HttpStatusCode.Created, requested.StatusCode);
        var authorization = await requested.Content.ReadFromJsonAsync<PublicTargetAuthorizationResponse>();
        Assert.NotNull(authorization);

        using var administrator = CreateAuthenticatedClient(tenantId, Guid.NewGuid(), UserRole.Admin);
        var approved = await administrator.PostAsJsonAsync(
            $"/api/v1/public-target-authorizations/{authorization!.Id}/approve",
            new PublicTargetAuthorizationApprovalRequest("ticket-schedule-1", "schedule-test", DateTimeOffset.UtcNow.AddDays(8)));
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);

        var expiresAt = DateTimeOffset.UtcNow.AddDays(7);
        var scopeRequest = new CreateScopeRequest(
            "scheduled-public-web-scope",
            [new TargetDefinition(TargetKind.Web, "https://example.com")],
            [],
            [WebAssessmentOperationProfiles.Passive],
            30,
            300,
            "ticket-schedule-1",
            expiresAt,
            false,
            null,
            [authorization.Id]);
        var createdScope = await analyst.PostAsJsonAsync("/api/v1/scopes", scopeRequest);
        Assert.Equal(HttpStatusCode.Created, createdScope.StatusCode);
        var scope = await createdScope.Content.ReadFromJsonAsync<ScopeResponse>();
        Assert.NotNull(scope);

        var request = new CreateAssessmentScheduleRequest(
            scope!.Id,
            WebAssessmentOperationProfiles.Passive,
            24,
            scope.ExpiresAt.AddTicks(-1));
        var createdSchedule = await analyst.PostAsJsonAsync("/api/v1/assessment-schedules", request);
        Assert.Equal(HttpStatusCode.Created, createdSchedule.StatusCode);
        var schedule = await createdSchedule.Content.ReadFromJsonAsync<AssessmentScheduleResponse>();
        Assert.NotNull(schedule);
        Assert.Equal(tenantId, scope.TenantId);
        Assert.Equal(scope.Id, schedule!.ScopeId);
        Assert.Equal(AssessmentScheduleStatus.Active, schedule.Status);
        Assert.NotNull(schedule.NextRunAt);

        var invalidEnd = request with { EndsAt = scope.ExpiresAt };
        var rejectedExpiry = await analyst.PostAsJsonAsync("/api/v1/assessment-schedules", invalidEnd);
        Assert.Equal(HttpStatusCode.BadRequest, rejectedExpiry.StatusCode);

        using var viewer = CreateAuthenticatedClient(tenantId, Guid.NewGuid(), UserRole.Viewer);
        var visible = await viewer.GetFromJsonAsync<List<AssessmentScheduleResponse>>("/api/v1/assessment-schedules");
        Assert.NotNull(visible);
        Assert.Contains(visible!, item => item.Id == schedule.Id);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await viewer.PostAsync($"/api/v1/assessment-schedules/{schedule.Id}/pause", content: null)).StatusCode);

        using var otherTenant = CreateAuthenticatedClient(Guid.NewGuid(), Guid.NewGuid(), UserRole.Viewer);
        var isolated = await otherTenant.GetFromJsonAsync<List<AssessmentScheduleResponse>>("/api/v1/assessment-schedules");
        Assert.NotNull(isolated);
        Assert.Empty(isolated!);
    }

    [Fact]
    public async Task Scheduled_reassessment_API_supports_the_full_reader_operator_and_notification_lifecycle()
    {
        var analystId = Guid.NewGuid();
        using var analyst = CreateAuthenticatedClient(tenantId, analystId, UserRole.SecurityAnalyst);
        var requested = await analyst.PostAsJsonAsync("/api/v1/public-target-authorizations",
            new PublicTargetAuthorizationRequest("https://schedule-lifecycle.example", "Approved recurring assessment lifecycle test"));
        Assert.Equal(HttpStatusCode.Created, requested.StatusCode);
        var authorization = await requested.Content.ReadFromJsonAsync<PublicTargetAuthorizationResponse>();
        Assert.NotNull(authorization);

        using var administrator = CreateAuthenticatedClient(tenantId, Guid.NewGuid(), UserRole.Admin);
        var approved = await administrator.PostAsJsonAsync(
            $"/api/v1/public-target-authorizations/{authorization!.Id}/approve",
            new PublicTargetAuthorizationApprovalRequest("ticket-schedule-lifecycle", "api-integration-test", DateTimeOffset.UtcNow.AddDays(8)));
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);

        var scopeRequest = new CreateScopeRequest(
            "scheduled-lifecycle-scope",
            [new TargetDefinition(TargetKind.Web, "https://schedule-lifecycle.example/")],
            [],
            [WebAssessmentOperationProfiles.Passive],
            30,
            300,
            "ticket-schedule-lifecycle",
            DateTimeOffset.UtcNow.AddDays(7),
            false,
            null,
            [authorization.Id]);
        var createdScope = await analyst.PostAsJsonAsync("/api/v1/scopes", scopeRequest);
        Assert.Equal(HttpStatusCode.Created, createdScope.StatusCode);
        var targetScope = await createdScope.Content.ReadFromJsonAsync<ScopeResponse>();
        Assert.NotNull(targetScope);

        var scheduleRequest = new CreateAssessmentScheduleRequest(
            targetScope!.Id,
            WebAssessmentOperationProfiles.Passive,
            24,
            targetScope.ExpiresAt.AddTicks(-1));
        var created = await analyst.PostAsJsonAsync("/api/v1/assessment-schedules", scheduleRequest);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var schedule = await created.Content.ReadFromJsonAsync<AssessmentScheduleResponse>();
        Assert.NotNull(schedule);

        var listed = await analyst.GetFromJsonAsync<List<AssessmentScheduleResponse>>("/api/v1/assessment-schedules");
        Assert.NotNull(listed);
        Assert.Contains(listed, item => item.Id == schedule!.Id);
        var initiallyEmptyHistory = await analyst.GetFromJsonAsync<List<AssessmentScheduleRunResponse>>(
            $"/api/v1/assessment-schedules/{schedule!.Id}/runs");
        Assert.NotNull(initiallyEmptyHistory);
        Assert.Empty(initiallyEmptyHistory);

        using var viewer = CreateAuthenticatedClient(tenantId, Guid.NewGuid(), UserRole.Viewer);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await viewer.PostAsync($"/api/v1/assessment-schedules/{schedule.Id}/pause", content: null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await viewer.PostAsync($"/api/v1/assessment-schedules/{schedule.Id}/resume", content: null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await viewer.PostAsync($"/api/v1/assessment-schedules/{schedule.Id}/disable", content: null)).StatusCode);

        var pausedResponse = await analyst.PostAsync($"/api/v1/assessment-schedules/{schedule.Id}/pause", content: null);
        Assert.Equal(HttpStatusCode.OK, pausedResponse.StatusCode);
        var paused = await pausedResponse.Content.ReadFromJsonAsync<AssessmentScheduleResponse>();
        Assert.NotNull(paused);
        Assert.Equal(AssessmentScheduleStatus.Paused, paused.Status);
        Assert.Null(paused.NextRunAt);

        var resumedResponse = await analyst.PostAsync($"/api/v1/assessment-schedules/{schedule.Id}/resume", content: null);
        Assert.Equal(HttpStatusCode.OK, resumedResponse.StatusCode);
        var resumed = await resumedResponse.Content.ReadFromJsonAsync<AssessmentScheduleResponse>();
        Assert.NotNull(resumed);
        Assert.Equal(AssessmentScheduleStatus.Active, resumed.Status);
        Assert.True(resumed.NextRunAt > DateTimeOffset.UtcNow);

        var pauseBeforeRevocation = await analyst.PostAsync(
            $"/api/v1/assessment-schedules/{schedule.Id}/pause", content: null);
        Assert.Equal(HttpStatusCode.OK, pauseBeforeRevocation.StatusCode);
        var revoked = await administrator.PostAsync(
            $"/api/v1/public-target-authorizations/{authorization.Id}/revoke", content: null);
        Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);

        var blockedResumeResponse = await analyst.PostAsync(
            $"/api/v1/assessment-schedules/{schedule.Id}/resume", content: null);
        Assert.Equal(HttpStatusCode.OK, blockedResumeResponse.StatusCode);
        var blockedResume = await blockedResumeResponse.Content.ReadFromJsonAsync<AssessmentScheduleResponse>();
        Assert.NotNull(blockedResume);
        Assert.Equal(AssessmentScheduleStatus.Blocked, blockedResume.Status);
        Assert.Null(blockedResume.NextRunAt);
        Assert.Contains("authorization changed", blockedResume.BlockedReason, StringComparison.OrdinalIgnoreCase);

        var run = new AssessmentScheduleRun(tenantId, schedule.Id, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow);
        run.MarkQueued(Guid.NewGuid(), Guid.NewGuid());
        var driftEvent = new AssessmentDriftEvent(tenantId, schedule.Id, run.Id,
            Guid.NewGuid(), Guid.NewGuid(), "NewFinding", new string('D', 64), null, FindingSeverity.High,
            "A new finding was detected by a completed scheduled assessment.", DateTimeOffset.UtcNow);
        var notification = new Notification(tenantId, "in-app",
            "Scheduled assessment drift: NewFinding. Review the event in the SentinelAI Schedules workspace.", driftEvent.Id);
        using (var seedScope = factory.Services.CreateScope())
        {
            var db = seedScope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.AssessmentScheduleRuns.Add(run);
            db.AssessmentDriftEvents.Add(driftEvent);
            db.Notifications.Add(notification);
            await db.SaveChangesAsync();
        }

        var history = await analyst.GetFromJsonAsync<List<AssessmentScheduleRunResponse>>(
            $"/api/v1/assessment-schedules/{schedule.Id}/runs");
        Assert.NotNull(history);
        Assert.Contains(history, item => item.Id == run.Id && item.Status == AssessmentScheduleRunStatus.Queued);

        var driftEvents = await analyst.GetFromJsonAsync<List<AssessmentDriftEventResponse>>("/api/v1/assessment-drift-events");
        Assert.NotNull(driftEvents);
        Assert.Contains(driftEvents, item => item.Id == driftEvent.Id && item.AcknowledgedAt is null);
        var notifications = await analyst.GetFromJsonAsync<List<AssessmentNotificationResponse>>("/api/v1/notifications");
        Assert.NotNull(notifications);
        Assert.Contains(notifications, item => item.EventId == driftEvent.Id && !item.IsRead);

        using var otherTenant = CreateAuthenticatedClient(Guid.NewGuid(), Guid.NewGuid(), UserRole.Viewer);
        Assert.Equal(HttpStatusCode.NotFound,
            (await otherTenant.GetAsync($"/api/v1/assessment-schedules/{schedule.Id}/runs")).StatusCode);
        Assert.Empty(await otherTenant.GetFromJsonAsync<List<AssessmentDriftEventResponse>>("/api/v1/assessment-drift-events") ?? []);
        Assert.Empty(await otherTenant.GetFromJsonAsync<List<AssessmentNotificationResponse>>("/api/v1/notifications") ?? []);

        Assert.Equal(HttpStatusCode.Forbidden,
            (await viewer.PostAsync($"/api/v1/assessment-drift-events/{driftEvent.Id}/acknowledge", content: null)).StatusCode);
        var acknowledged = await analyst.PostAsync(
            $"/api/v1/assessment-drift-events/{driftEvent.Id}/acknowledge", content: null);
        Assert.Equal(HttpStatusCode.NoContent, acknowledged.StatusCode);

        var acknowledgedEvents = await analyst.GetFromJsonAsync<List<AssessmentDriftEventResponse>>("/api/v1/assessment-drift-events");
        Assert.NotNull(acknowledgedEvents);
        Assert.Contains(acknowledgedEvents, item => item.Id == driftEvent.Id && item.AcknowledgedAt is not null);
        var readNotifications = await analyst.GetFromJsonAsync<List<AssessmentNotificationResponse>>("/api/v1/notifications");
        Assert.NotNull(readNotifications);
        Assert.Contains(readNotifications, item => item.EventId == driftEvent.Id && item.IsRead);

        var disabledResponse = await analyst.PostAsync($"/api/v1/assessment-schedules/{schedule.Id}/disable", content: null);
        Assert.Equal(HttpStatusCode.OK, disabledResponse.StatusCode);
        var disabled = await disabledResponse.Content.ReadFromJsonAsync<AssessmentScheduleResponse>();
        Assert.NotNull(disabled);
        Assert.Equal(AssessmentScheduleStatus.Disabled, disabled.Status);
        Assert.Null(disabled.NextRunAt);
    }

    [Fact]
    public async Task Finding_analysis_API_uses_the_configured_provider_and_enforces_operator_reader_and_tenant_boundaries()
    {
        var provider = new IntegrationFakeProvider();
        using var configuredFactory = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IAIProviderFactory>();
                services.AddSingleton<IAIProviderFactory>(new AIProviderFactory([provider]));
            }));

        var findingId = Guid.NewGuid();
        var noEvidenceFindingId = Guid.NewGuid();
        using (var seedScope = configuredFactory.Services.CreateScope())
        {
            var db = seedScope.ServiceProvider.GetRequiredService<AppDbContext>();
            var finding = new Finding(tenantId, null, "Missing security header", FindingSeverity.Medium);
            finding.ConfigureAssessmentDetails(Guid.NewGuid(), "security-headers", "High",
                "https://example.test/", "GET", null, "Stored finding description", "Stored impact",
                null, "Configure the missing header.", null, WebCheckStatus.FindingDetected);
            var evidence = new Evidence(tenantId, finding.Id, "http-response",
                "The response headers did not contain the expected security header.", new string('A', 64));
            evidence.ConfigureContent("HTTP/1.1 200 OK\nContent-Type: text/html", "text/plain");

            var noEvidence = new Finding(tenantId, null, "Finding without evidence", FindingSeverity.Low);
            noEvidence.ConfigureAssessmentDetails(Guid.NewGuid(), "cookies", "Medium",
                "https://example.test/login", "GET", null, "No evidence has been stored.", "Unknown impact",
                null, "Collect evidence first.", null, WebCheckStatus.PotentialFinding);
            findingId = finding.Id;
            noEvidenceFindingId = noEvidence.Id;
            db.AddRange(finding, evidence, noEvidence);
            await db.SaveChangesAsync();
        }

        using var analyst = CreateAuthenticatedClient(configuredFactory, tenantId, userId, UserRole.SecurityAnalyst);
        var request = new AnalyzeFindingRequest("test");
        var created = await analyst.PostAsJsonAsync($"/api/v1/findings/{findingId}/ai-analysis", request);
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        var analysis = await created.Content.ReadFromJsonAsync<FindingAIAnalysisResponse>();
        Assert.NotNull(analysis);
        Assert.Equal("test", analysis!.Provider);
        Assert.Equal("integration-test-model", analysis.Model);
        Assert.Equal("finding-analysis-v1", analysis.PromptTemplateVersion);
        Assert.Equal(64, analysis.EvidenceSha256.Length);
        Assert.Equal(1, provider.CallCount);

        using var viewer = CreateAuthenticatedClient(configuredFactory, tenantId, Guid.NewGuid(), UserRole.Viewer);
        var history = await viewer.GetFromJsonAsync<List<FindingAIAnalysisResponse>>(
            $"/api/v1/findings/{findingId}/ai-analyses");
        Assert.NotNull(history);
        Assert.Contains(history, item => item.Id == analysis.Id);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await viewer.PostAsJsonAsync($"/api/v1/findings/{findingId}/ai-analysis", request)).StatusCode);

        using var otherTenant = CreateAuthenticatedClient(configuredFactory, Guid.NewGuid(), Guid.NewGuid(), UserRole.Viewer);
        Assert.Equal(HttpStatusCode.NotFound,
            (await otherTenant.GetAsync($"/api/v1/findings/{findingId}/ai-analyses")).StatusCode);

        var withoutEvidence = await analyst.PostAsJsonAsync(
            $"/api/v1/findings/{noEvidenceFindingId}/ai-analysis", request);
        Assert.Equal(HttpStatusCode.Conflict, withoutEvidence.StatusCode);
        Assert.Equal(1, provider.CallCount);

        using (var verifyScope = configuredFactory.Services.CreateScope())
        {
            var db = verifyScope.ServiceProvider.GetRequiredService<AppDbContext>();
            var stored = await db.FindingAIAnalyses.SingleAsync(x => x.Id == analysis.Id);
            Assert.Equal(tenantId, stored.TenantId);
            Assert.Equal(userId, stored.ActorId);
            Assert.Equal(FindingSeverity.Medium,
                (await db.Findings.SingleAsync(x => x.Id == findingId)).Severity);
            Assert.Empty(await db.FindingAIAnalyses.Where(x => x.FindingId == noEvidenceFindingId).ToListAsync());
        }
    }

    [Fact]
    public async Task Advisory_report_API_is_opt_in_publishes_persisted_content_and_preserves_tenant_boundary()
    {
        var artifacts = new ReportRouteArtifactStore();
        var generator = new ReportRouteGenerator(artifacts);
        using var reportFactory = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IAssessmentArtifactStore>();
                services.AddSingleton<IAssessmentArtifactStore>(artifacts);
                services.RemoveAll<IHtmlReportGenerator>();
                services.AddSingleton<IHtmlReportGenerator>(generator);
            }));

        var tenant = new Tenant("AI advisory report API tenant");
        var scope = new TargetScope(tenant.Id, "AI advisory report scope", userId, DateTimeOffset.UtcNow.AddDays(2));
        scope.Configure([new TargetDefinition(TargetKind.Web, "https://report-api.example/")], [],
            [WebAssessmentOperationProfiles.Passive], 30, 300, "approved report API test", false);
        scope.ConfigureWebHosting(WebHostingMode.Public);
        var job = new AgentJob(tenant.Id, scope.Id, userId, WebAssessmentOperationProfiles.Passive);
        var assessment = new WebAssessment(tenant.Id, job.Id, scope.Id, "https://report-api.example/",
            WebAssessmentOperationProfiles.Passive, WebHostingMode.Public);
        const string defaultReportKey = "default-report.html";
        assessment.Complete(defaultReportKey, 0);

        using (var seedScope = reportFactory.Services.CreateScope())
        {
            var db = seedScope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.AddRange(tenant, scope, job, assessment);
            await db.SaveChangesAsync();
        }

        artifacts.SeedPublished(tenant.Id, assessment.Id, defaultReportKey, "<h1>Default report</h1>");
        using var reader = CreateAuthenticatedClient(reportFactory, tenant.Id, Guid.NewGuid(), UserRole.Viewer);

        var defaultResponse = await reader.GetAsync($"/api/v1/web-assessments/{assessment.Id}/report");
        Assert.Equal(HttpStatusCode.OK, defaultResponse.StatusCode);
        Assert.Equal("text/html", defaultResponse.Content.Headers.ContentType?.MediaType);
        Assert.Contains("Default report", await defaultResponse.Content.ReadAsStringAsync());
        Assert.Equal(0, generator.CallCount); // Default export never invokes the advisory generator.

        var advisoryResponse = await reader.GetAsync(
            $"/api/v1/web-assessments/{assessment.Id}/report?includeAiSummaries=true");
        Assert.Equal(HttpStatusCode.OK, advisoryResponse.StatusCode);
        Assert.Equal("text/html", advisoryResponse.Content.Headers.ContentType?.MediaType);
        var advisoryHtml = await advisoryResponse.Content.ReadAsStringAsync();
        Assert.Contains("AI advisory summary · Human review required", advisoryHtml);
        Assert.Equal(1, generator.CallCount);
        Assert.True(generator.LastIncludeAdvisorySummaries);
        Assert.NotNull(artifacts.LastPublishedKey);
        Assert.Contains(artifacts.LastPublishedKey, artifacts.DiscardedKeys);
        Assert.Null(artifacts.GetPublished(tenant.Id, assessment.Id, artifacts.LastPublishedKey));

        using var otherTenant = CreateAuthenticatedClient(Guid.NewGuid(), Guid.NewGuid(), UserRole.Viewer);
        Assert.Equal(HttpStatusCode.NotFound,
            (await otherTenant.GetAsync($"/api/v1/web-assessments/{assessment.Id}/report?includeAiSummaries=true")).StatusCode);
        Assert.Equal(1, generator.CallCount);
    }

    [Fact]
    public async Task Worker_can_register_and_heartbeat_through_authenticated_endpoint()
    {
        using var administrator = CreateAuthenticatedClient(tenantId, Guid.NewGuid(), UserRole.Admin);
        var provision = await administrator.PostAsJsonAsync("/api/v1/workers/test-worker/provision", new WorkerProvisionRequest("test", ["passive-mock", "passive-inventory", "cancellation"]));
        Assert.Equal(HttpStatusCode.OK, provision.StatusCode);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Tenant-Id", tenantId.ToString());
        client.DefaultRequestHeaders.Add("X-User-Id", Guid.NewGuid().ToString());
        client.DefaultRequestHeaders.Add("X-Role", "Worker");
        client.DefaultRequestHeaders.Add("X-Worker-Id", "test-worker");
        var register = await client.PostAsJsonAsync("/api/v1/workers/register", new WorkerRegistrationRequest("test-worker", "test", ["passive-mock", "passive-inventory", "cancellation"]));
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);
        var worker = await register.Content.ReadFromJsonAsync<WorkerResponse>();
        Assert.NotNull(worker);
        Assert.Equal(WorkerStatus.Healthy, worker.Status);
        var heartbeat = await client.PostAsJsonAsync("/api/v1/workers/heartbeat", new WorkerHeartbeatRequest("test-worker", 0, 2));
        Assert.Equal(HttpStatusCode.OK, heartbeat.StatusCode);
    }

    [Fact]
    public async Task Worker_registration_cannot_self_grant_capabilities_and_admin_provisioning_is_authoritative()
    {
        var workerId = $"unprovisioned-{Guid.NewGuid():N}";
        using var worker = CreateAuthenticatedClient(tenantId, Guid.NewGuid(), UserRole.Worker);
        worker.DefaultRequestHeaders.Add("X-Worker-Id", workerId);
        var rejected = await worker.PostAsJsonAsync("/api/v1/workers/register", new WorkerRegistrationRequest(workerId, "test", ["web-assessment", "private-web-assessment"]));
        Assert.Equal(HttpStatusCode.NotFound, rejected.StatusCode);

        using var administrator = CreateAuthenticatedClient(tenantId, Guid.NewGuid(), UserRole.Admin);
        var provisioned = await administrator.PostAsJsonAsync($"/api/v1/workers/{workerId}/provision", new WorkerProvisionRequest("test", ["web-assessment", "private-web-assessment"], ["10.0.0.0/8"]));
        Assert.Equal(HttpStatusCode.OK, provisioned.StatusCode);
        var state = await provisioned.Content.ReadFromJsonAsync<WorkerResponse>();
        Assert.NotNull(state);
        Assert.Contains("web-assessment", state!.Capabilities);
        Assert.True(state.PrivateAssessmentApproved);

        var registration = await worker.PostAsJsonAsync("/api/v1/workers/register", new WorkerRegistrationRequest(workerId, "test", ["web-assessment", "private-web-assessment"]));
        Assert.Equal(HttpStatusCode.OK, registration.StatusCode);
        var registered = await registration.Content.ReadFromJsonAsync<WorkerResponse>();
        Assert.NotNull(registered);
        Assert.Contains("private-web-assessment", registered!.Capabilities);

        var updated = await administrator.PostAsJsonAsync($"/api/v1/workers/{workerId}/provision", new WorkerProvisionRequest("test-2", ["web-assessment"]));
        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        var updatedState = await updated.Content.ReadFromJsonAsync<WorkerResponse>();
        Assert.NotNull(updatedState);
        Assert.Contains("web-assessment", updatedState!.Capabilities);
        Assert.DoesNotContain("private-web-assessment", updatedState.Capabilities);
        Assert.False(updatedState.PrivateAssessmentApproved);
    }

    [Fact]
    public async Task Private_worker_revocation_removes_effective_authorization_immediately()
    {
        var workerId = $"revoke-{Guid.NewGuid():N}";
        using var administrator = CreateAuthenticatedClient(tenantId, Guid.NewGuid(), UserRole.Admin);
        var provisioned = await administrator.PostAsJsonAsync($"/api/v1/workers/{workerId}/provision", new WorkerProvisionRequest("test", ["web-assessment", "private-web-assessment"], ["10.0.0.0/8"]));
        Assert.Equal(HttpStatusCode.OK, provisioned.StatusCode);
        var revoked = await administrator.PostAsJsonAsync($"/api/v1/workers/{workerId}/private-authorization", new PrivateWorkerAuthorizationRequest([], false));
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        var state = await revoked.Content.ReadFromJsonAsync<WorkerResponse>();
        Assert.NotNull(state);
        Assert.False(state!.PrivateAssessmentApproved);
        Assert.Empty(state.ApprovedPrivateNetworkRanges ?? []);
    }

    [Fact]
    public async Task Private_web_assessment_requires_enrolled_worker_and_is_tenant_scoped()
    {
        var workerId = $"private-web-{Guid.NewGuid():N}";
        using var administrator = CreateAuthenticatedClient(tenantId, Guid.NewGuid(), UserRole.Admin);
        var provision = await administrator.PostAsJsonAsync($"/api/v1/workers/{workerId}/provision", new WorkerProvisionRequest("3.1", ["web-assessment", "private-web-assessment", "cancellation"], ["10.0.0.0/8"]));
        Assert.Equal(HttpStatusCode.OK, provision.StatusCode);
        using var workerClient = CreateAuthenticatedClient(tenantId, Guid.NewGuid(), UserRole.Worker);
        workerClient.DefaultRequestHeaders.Add("X-Worker-Id", workerId);
        var registration = await workerClient.PostAsJsonAsync("/api/v1/workers/register", new WorkerRegistrationRequest(workerId, "3.1", ["web-assessment", "private-web-assessment", "cancellation"]));
        Assert.Equal(HttpStatusCode.OK, registration.StatusCode);

        using var operatorClient = CreateAuthenticatedClient(tenantId, userId, UserRole.SecurityAnalyst);
        var created = await operatorClient.PostAsJsonAsync("/api/v1/web-assessments", new CreateWebAssessmentRequest("private app", "https://myapp.internal", WebHostingMode.Private, workerId, "web-assessment-passive", [], 10, 120, "private-lab-approval", DateTimeOffset.UtcNow.AddHours(1), false, null, ["10.0.0.0/8"]));
        Assert.Equal(HttpStatusCode.Accepted, created.StatusCode);
        var assessment = await created.Content.ReadFromJsonAsync<WebAssessmentResponse>();
        Assert.NotNull(assessment);
        Assert.NotEqual(Guid.Empty, assessment!.ScopeId);

        var filteredAssessments = await operatorClient.GetFromJsonAsync<PagedResponse<WebAssessmentResponse>>(
            $"/api/v1/web-assessments?search=myapp.internal&status={assessment.Status}");
        Assert.NotNull(filteredAssessments);
        Assert.Contains(filteredAssessments.Items, item => item.Id == assessment.Id);
        Assert.Equal(1, filteredAssessments.TotalCount);

        using var otherTenant = CreateAuthenticatedClient(Guid.NewGuid(), Guid.NewGuid(), UserRole.Viewer);
        Assert.Equal(HttpStatusCode.NotFound, (await otherTenant.GetAsync($"/api/v1/web-assessments/{assessment.Id}")).StatusCode);
    }

    [Fact]
    public async Task Reader_can_retrieve_seeded_assets_and_findings_with_pagination_and_tenant_isolation()
    {
        var otherTenantId = Guid.NewGuid();
        await SeedInventoryAsync(tenantId, otherTenantId);
        using var client = CreateAuthenticatedClient(tenantId, userId, UserRole.Viewer);

        var assetsResponse = await client.GetAsync("/api/v1/assets?page=1&pageSize=25");
        var findingsResponse = await client.GetAsync("/api/v1/findings?page=1&pageSize=25");
        Assert.Equal(HttpStatusCode.OK, assetsResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, findingsResponse.StatusCode);
        var assets = await assetsResponse.Content.ReadFromJsonAsync<PagedResponse<AssetResponse>>();
        var findings = await findingsResponse.Content.ReadFromJsonAsync<PagedResponse<FindingResponse>>();
        Assert.NotNull(assets);
        Assert.NotNull(findings);
        Assert.Single(assets.Items);
        Assert.Equal("10.10.0.5", assets.Items.Single().Address);
        Assert.Single(findings.Items);
        Assert.Equal("Seeded finding", findings.Items.Single().Title);
        var onlineOnly = await client.GetFromJsonAsync<PagedResponse<AssetResponse>>("/api/v1/assets?status=Online");
        var unconfirmedForTenant = await client.GetFromJsonAsync<PagedResponse<AssetResponse>>("/api/v1/assets?status=Unconfirmed");
        Assert.NotNull(onlineOnly);
        Assert.NotNull(unconfirmedForTenant);
        Assert.Equal(1, onlineOnly.TotalCount);
        Assert.Equal(0, unconfirmedForTenant.TotalCount);

        var services = await client.GetFromJsonAsync<List<AssetServiceResponse>>($"/api/v1/assets/{assets.Items.Single().Id}/services");
        Assert.NotNull(services);
        var service = Assert.Single(services);
        Assert.Equal(443, service.Port);
        Assert.Equal("https", service.Protocol);
        Assert.True(assets.Items.Single().IsOnline);
        Assert.NotNull(assets.Items.Single().LastSuccessfulReachabilityAt);

        using var otherClient = CreateAuthenticatedClient(otherTenantId, Guid.NewGuid(), UserRole.Viewer);
        var otherAssets = await otherClient.GetFromJsonAsync<PagedResponse<AssetResponse>>("/api/v1/assets");
        var otherFindings = await otherClient.GetFromJsonAsync<PagedResponse<FindingResponse>>("/api/v1/findings");
        Assert.NotNull(otherAssets);
        Assert.NotNull(otherFindings);
        Assert.Single(otherAssets.Items);
        Assert.Equal("10.20.0.5", otherAssets.Items.Single().Address);
        var otherUnconfirmed = await otherClient.GetFromJsonAsync<PagedResponse<AssetResponse>>("/api/v1/assets?status=Unconfirmed");
        Assert.NotNull(otherUnconfirmed);
        Assert.Single(otherUnconfirmed.Items);
        Assert.Empty(otherFindings.Items);
        var foreignServices = await otherClient.GetAsync($"/api/v1/assets/{assets.Items.Single().Id}/services");
        Assert.Equal(HttpStatusCode.NotFound, foreignServices.StatusCode);
    }

    [Fact]
    public async Task Empty_inventory_returns_success_with_empty_items_for_reader()
    {
        using var client = CreateAuthenticatedClient(Guid.NewGuid(), Guid.NewGuid(), UserRole.Viewer);

        var assets = await client.GetAsync("/api/v1/assets");
        var findings = await client.GetAsync("/api/v1/findings");
        Assert.Equal(HttpStatusCode.OK, assets.StatusCode);
        Assert.Equal(HttpStatusCode.OK, findings.StatusCode);
        Assert.Empty((await assets.Content.ReadFromJsonAsync<PagedResponse<AssetResponse>>())!.Items);
        Assert.Empty((await findings.Content.ReadFromJsonAsync<PagedResponse<FindingResponse>>())!.Items);
    }

    [Fact]
    public async Task Invalid_inventory_page_values_are_normalized()
    {
        using var client = CreateAuthenticatedClient(Guid.NewGuid(), Guid.NewGuid(), UserRole.Viewer);

        var response = await client.GetFromJsonAsync<PagedResponse<AssetResponse>>("/api/v1/assets?page=-10&pageSize=0");

        Assert.NotNull(response);
        Assert.Equal(1, response.Page);
        Assert.Equal(1, response.PageSize);
    }

    [Fact]
    public async Task Inventory_endpoints_require_authentication_and_allow_reader_roles()
    {
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/v1/assets")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/v1/findings")).StatusCode);

        using var reader = CreateAuthenticatedClient(Guid.NewGuid(), Guid.NewGuid(), UserRole.Viewer);
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync("/api/v1/assets")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync("/api/v1/findings")).StatusCode);
    }

    [Fact]
    public async Task Dashboard_summary_returns_live_tenant_metrics()
    {
        var testTenant = Guid.NewGuid();
        var otherTenant = Guid.NewGuid();
        await SeedInventoryAsync(testTenant, otherTenant);

        using var client = CreateAuthenticatedClient(testTenant, Guid.NewGuid(), UserRole.Viewer);
        var response = await client.GetAsync("/api/v1/dashboard/summary");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var summary = await response.Content.ReadFromJsonAsync<DashboardSummaryResponse>();
        Assert.NotNull(summary);
        Assert.Equal(1, summary.AssetsObserved);
        Assert.Equal(1, summary.ReachabilityConfirmedAssets);
        Assert.Equal(1, summary.ObservedServices);
        Assert.Equal(1, summary.TotalFindings);
        Assert.Equal(1, summary.HighFindings);
        Assert.Equal(0, summary.CriticalFindings);
    }

    [Fact]
    public async Task Scans_endpoint_returns_paginated_summary_for_tenant()
    {
        var testTenant = Guid.NewGuid();
        using var client = CreateAuthenticatedClient(testTenant, userId, UserRole.SecurityAnalyst);

        var scope = new CreateScopeRequest("scans-test-scope", [new TargetDefinition(TargetKind.Network, "10.0.0.0/24")], [], ["mock-passive"], 30, 300, "ticket-scans", DateTimeOffset.UtcNow.AddHours(1));
        var scopeResp = await client.PostAsJsonAsync("/api/v1/scopes", scope);
        Assert.Equal(HttpStatusCode.Created, scopeResp.StatusCode);
        var createdScope = await scopeResp.Content.ReadFromJsonAsync<ScopeResponse>();

        var scanResp = await client.PostAsJsonAsync("/api/v1/scans", new CreateScanRequest(createdScope!.Id, "mock-passive"));
        Assert.Equal(HttpStatusCode.Accepted, scanResp.StatusCode);

        var createdScan = await scanResp.Content.ReadFromJsonAsync<ScanResponse>();
        Assert.NotNull(createdScan);

        var listResp = await client.GetAsync("/api/v1/scans?page=1&pageSize=25");
        Assert.Equal(HttpStatusCode.OK, listResp.StatusCode);

        var pagedScans = await listResp.Content.ReadFromJsonAsync<PagedResponse<ScanJobSummaryResponse>>();
        Assert.NotNull(pagedScans);
        Assert.True(pagedScans.TotalCount >= 1);
        Assert.Contains(pagedScans.Items, s => s.ScopeName == "scans-test-scope");

        var byScopeName = await client.GetFromJsonAsync<PagedResponse<ScanJobSummaryResponse>>("/api/v1/scans?search=scans-test-scope");
        Assert.NotNull(byScopeName);
        Assert.Contains(byScopeName.Items, s => s.ScopeName == "scans-test-scope");

        var byJobId = await client.GetFromJsonAsync<PagedResponse<ScanJobSummaryResponse>>($"/api/v1/scans?search={createdScan!.Id}");
        Assert.NotNull(byJobId);
        Assert.Contains(byJobId.Items, s => s.Id == createdScan.Id);
    }

    [Fact]
    public async Task Health_and_provider_readiness_report_verified_facts_not_hardcoded_success()
    {
        using var client = CreateAuthenticatedClient(Guid.NewGuid(), Guid.NewGuid(), UserRole.Viewer);

        var health = await client.GetFromJsonAsync<JsonElement>("/api/v1/monitoring/health");
        Assert.Equal("connected", health.GetProperty("databaseStatus").GetString());
        Assert.Equal("configured-in-memory", health.GetProperty("messagingStatus").GetString());
        Assert.Equal("registered", health.GetProperty("assessmentEngineStatus").GetString());

        var providers = await client.GetFromJsonAsync<JsonElement>("/api/v1/ai/providers");
        Assert.False(providers.GetProperty("connectivityVerified").GetBoolean());
        Assert.False(providers.GetProperty("inferenceImplemented").GetBoolean());
        Assert.Equal("advisory-only", providers.GetProperty("executionMode").GetString());
    }

    [Fact]
    public async Task Finding_detail_returns_complete_evidence_and_context()
    {
        var testTenant = Guid.NewGuid();
        var testUser = Guid.NewGuid();
        Guid findingId;

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var targetScope = new TargetScope(testTenant, "finding-test-scope", testUser, DateTimeOffset.UtcNow.AddHours(1));
            var finding = new Finding(testTenant, null, "Test Injection Flaw", FindingSeverity.Critical);
            var evidence = new Evidence(testTenant, finding.Id, "http-traffic", "Injected canary observed in response body", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");

            db.AddRange(targetScope, finding, evidence);
            await db.SaveChangesAsync();
            findingId = finding.Id;
        }

        using var client = CreateAuthenticatedClient(testTenant, testUser, UserRole.Viewer);
        var response = await client.GetAsync($"/api/v1/findings/{findingId}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var detail = await response.Content.ReadFromJsonAsync<FindingDetailResponse>();
        Assert.NotNull(detail);
        Assert.Equal("Test Injection Flaw", detail.Title);
        Assert.Equal(FindingSeverity.Critical, detail.Severity);
        Assert.Single(detail.Evidence);
        Assert.Equal("http-traffic", detail.Evidence.First().Source);

        using var otherClient = CreateAuthenticatedClient(Guid.NewGuid(), Guid.NewGuid(), UserRole.Viewer);
        var forbiddenResp = await otherClient.GetAsync($"/api/v1/findings/{findingId}");
        Assert.Equal(HttpStatusCode.NotFound, forbiddenResp.StatusCode);
    }

    [Fact]
    public async Task Administrator_can_self_approve_public_target_when_single_admin_policy_is_enabled()
    {
        var tenant = Guid.NewGuid();
        var administrator = Guid.NewGuid();
        using var localFactory = factory.WithWebHostBuilder(builder =>
            builder.UseEnvironment("Development")
                .UseSetting("Database:Provider", "InMemory")
                .UseSetting("Authorization:AllowAdminSelfApproval", "true"));

        using var adminClient = CreateAuthenticatedClient(localFactory, tenant, administrator, UserRole.Admin);
        var requestResponse = await adminClient.PostAsJsonAsync(
            "/api/v1/public-target-authorizations",
            new PublicTargetAuthorizationRequest("https://owned.example.test", "Administrator-confirmed authorized test target"));
        Assert.Equal(HttpStatusCode.Created, requestResponse.StatusCode);
        var requested = await requestResponse.Content.ReadFromJsonAsync<PublicTargetAuthorizationResponse>();
        Assert.NotNull(requested);
        Assert.Equal(PublicTargetAuthorizationStatus.Requested, requested.Status);

        var approvalResponse = await adminClient.PostAsJsonAsync(
            $"/api/v1/public-target-authorizations/{requested.Id}/approve",
            new PublicTargetAuthorizationApprovalRequest(
                "admin-authorization-attestation",
                "administrator-self-approval",
                DateTimeOffset.UtcNow.AddHours(1)));
        Assert.Equal(HttpStatusCode.OK, approvalResponse.StatusCode);
        var approved = await approvalResponse.Content.ReadFromJsonAsync<PublicTargetAuthorizationResponse>();
        Assert.NotNull(approved);
        Assert.Equal(PublicTargetAuthorizationStatus.Approved, approved.Status);
        Assert.Equal(administrator, approved.ApprovedBy);
    }

    [Fact]
    public async Task Scheduled_reassessment_executes_through_the_in_process_worker_pipeline()
    {
        var tenant = Guid.NewGuid();
        var requester = Guid.NewGuid();
        var approver = Guid.NewGuid();
        var probe = new InProcessWorkerProbe();

        using var localFactory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development")
                .UseSetting("Database:Provider", "InMemory")
                .UseSetting("Database:InMemoryName", $"scheduled-worker-{Guid.NewGuid():N}")
                .UseSetting("Messaging:Mode", "InMemory")
                .UseSetting("Worker:RunInProcess", "true")
                .UseSetting("Scheduling:Enabled", "false");
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IHostAddressResolver>();
                services.AddSingleton<IHostAddressResolver, FixedPublicAddressResolver>();
                services.RemoveAll<IWebAssessmentEngine>();
                services.AddSingleton(probe);
                services.AddScoped<IWebAssessmentEngine, InProcessWorkerProbeEngine>();
            });
        });

        using var requesterClient = CreateAuthenticatedClient(localFactory, tenant, requester, UserRole.SecurityAnalyst);
        using var approverClient = CreateAuthenticatedClient(localFactory, tenant, approver, UserRole.Admin);

        var authorizationResponse = await requesterClient.PostAsJsonAsync(
            "/api/v1/public-target-authorizations",
            new PublicTargetAuthorizationRequest("https://scheduled-execution.example", "Authorized scheduled execution integration test"));
        Assert.Equal(HttpStatusCode.Created, authorizationResponse.StatusCode);
        var authorization = await authorizationResponse.Content.ReadFromJsonAsync<PublicTargetAuthorizationResponse>();
        Assert.NotNull(authorization);

        var approvalResponse = await approverClient.PostAsJsonAsync(
            $"/api/v1/public-target-authorizations/{authorization!.Id}/approve",
            new PublicTargetAuthorizationApprovalRequest(
                "scheduled-execution-evidence",
                "separate-admin-approval",
                DateTimeOffset.UtcNow.AddDays(6)));
        Assert.Equal(HttpStatusCode.OK, approvalResponse.StatusCode);

        var scopeResponse = await requesterClient.PostAsJsonAsync("/api/v1/scopes",
            new CreateScopeRequest(
                "scheduled-execution-scope",
                [new TargetDefinition(TargetKind.Web, "https://scheduled-execution.example")],
                [],
                [WebAssessmentOperationProfiles.Passive],
                30,
                300,
                "scheduled-execution-evidence",
                DateTimeOffset.UtcNow.AddDays(5),
                false,
                null,
                [authorization.Id]));
        Assert.Equal(HttpStatusCode.Created, scopeResponse.StatusCode);
        var scope = await scopeResponse.Content.ReadFromJsonAsync<ScopeResponse>();
        Assert.NotNull(scope);

        var scheduleResponse = await requesterClient.PostAsJsonAsync("/api/v1/assessment-schedules",
            new CreateAssessmentScheduleRequest(
                scope!.Id,
                WebAssessmentOperationProfiles.Passive,
                24,
                scope.ExpiresAt.AddTicks(-1)));
        Assert.Equal(HttpStatusCode.Created, scheduleResponse.StatusCode);
        var schedule = await scheduleResponse.Content.ReadFromJsonAsync<AssessmentScheduleResponse>();
        Assert.NotNull(schedule);

        // Make the persisted occurrence due without changing the authorization or schedule boundary.
        using (var seedScope = localFactory.Services.CreateScope())
        {
            var db = seedScope.ServiceProvider.GetRequiredService<AppDbContext>();
            var persisted = await db.AssessmentSchedules.SingleAsync(x => x.Id == schedule!.Id);
            db.Entry(persisted).Property(x => x.NextRunAt).CurrentValue = DateTimeOffset.UtcNow.AddMinutes(-1);
            await db.SaveChangesAsync();
        }

        // Invoke the real processor registered by the API. In-memory mode uses the immediate
        // scan-job queue, while the normal in-process worker still performs lease and authorization checks.
        await using (var schedulerScope = localFactory.Services.CreateAsyncScope())
        {
            var processor = schedulerScope.ServiceProvider.GetRequiredService<AssessmentScheduleProcessor>();
            await processor.RunOnceAsync();
        }

        var executionSignal = await Task.WhenAny(probe.Executed.Task, Task.Delay(TimeSpan.FromSeconds(10)));
        Assert.Same(probe.Executed.Task, executionSignal);
        var execution = await probe.Executed.Task;
        Assert.Equal("in-process", execution.WorkerIdentity);
        Assert.Contains(WebAssessmentCapabilities.WebAssessment, execution.WorkerCapabilities);
        Assert.True(execution.LeaseWasValid);
        Assert.True(execution.LiveAuthorizationWasValid);

        WebAssessmentResponse? final = null;
        Guid assessmentId = Guid.Empty;
        using (var inspectScope = localFactory.Services.CreateScope())
        {
            var db = inspectScope.ServiceProvider.GetRequiredService<AppDbContext>();
            var queuedRun = await db.AssessmentScheduleRuns.SingleAsync(x => x.ScheduleId == schedule!.Id);
            Assert.Equal(AssessmentScheduleRunStatus.Queued, queuedRun.Status);
            Assert.NotNull(queuedRun.AssessmentId);
            assessmentId = queuedRun.AssessmentId!.Value;
        }

        for (var attempt = 0; attempt < 50; attempt++)
        {
            var response = await requesterClient.GetAsync($"/api/v1/web-assessments/{assessmentId}");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            final = await response.Content.ReadFromJsonAsync<WebAssessmentResponse>();
            if (final?.Status is WebAssessmentStatus.Completed or WebAssessmentStatus.Failed) break;
            await Task.Delay(100);
        }

        Assert.NotNull(final);
        Assert.Equal(WebAssessmentStatus.Completed, final.Status);
        Assert.Equal(ScanJobStatus.Completed, final.JobStatus);

        await using (var reconcileScope = localFactory.Services.CreateAsyncScope())
        {
            var processor = reconcileScope.ServiceProvider.GetRequiredService<AssessmentScheduleProcessor>();
            await processor.RunOnceAsync();
        }

        using (var verifyScope = localFactory.Services.CreateScope())
        {
            var db = verifyScope.ServiceProvider.GetRequiredService<AppDbContext>();
            var run = await db.AssessmentScheduleRuns.SingleAsync(x => x.ScheduleId == schedule!.Id);
            var persistedAssessment = await db.WebAssessments.SingleAsync(x => x.Id == assessmentId);
            var persistedJob = await db.AgentJobs.SingleAsync(x => x.Id == run.JobId);
            var persistedSchedule = await db.AssessmentSchedules.SingleAsync(x => x.Id == schedule.Id);

            Assert.Equal(AssessmentScheduleRunStatus.Completed, run.Status);
            Assert.NotNull(run.CompletedAt);
            Assert.Equal(WebAssessmentStatus.Completed, persistedAssessment.Status);
            Assert.Equal(ScanJobStatus.Completed, persistedJob.Status);
            Assert.Equal("Completed", persistedSchedule.LastResult);
            Assert.Empty(await db.AssessmentDriftEvents.Where(x => x.ScheduleRunId == run.Id).ToListAsync());
            Assert.Single(await db.OutboxMessages.Where(x => x.TenantId == tenant).ToListAsync());
        }
    }

    [Fact]
    public async Task In_process_worker_completes_an_authorized_public_web_assessment()
    {
        var tenant = Guid.NewGuid();
        var requester = Guid.NewGuid();
        var approver = Guid.NewGuid();
        var probe = new InProcessWorkerProbe();

        using var localFactory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development")
                .UseSetting("Database:Provider", "InMemory")
                .UseSetting("Messaging:Mode", "InMemory")
                .UseSetting("Worker:RunInProcess", "true");
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IHostAddressResolver>();
                services.AddSingleton<IHostAddressResolver, FixedPublicAddressResolver>();
                services.RemoveAll<IWebAssessmentEngine>();
                services.AddSingleton(probe);
                services.AddScoped<IWebAssessmentEngine, InProcessWorkerProbeEngine>();
            });
        });

        using var requesterClient = CreateAuthenticatedClient(localFactory, tenant, requester, UserRole.SecurityAnalyst);
        using var approverClient = CreateAuthenticatedClient(localFactory, tenant, approver, UserRole.Admin);

        var authorizationResponse = await requesterClient.PostAsJsonAsync(
            "/api/v1/public-target-authorizations",
            new PublicTargetAuthorizationRequest("https://example.com", "Integration test owned target"));
        Assert.Equal(HttpStatusCode.Created, authorizationResponse.StatusCode);
        var authorization = await authorizationResponse.Content.ReadFromJsonAsync<PublicTargetAuthorizationResponse>();
        Assert.NotNull(authorization);

        var approvalResponse = await approverClient.PostAsJsonAsync(
            $"/api/v1/public-target-authorizations/{authorization.Id}/approve",
            new PublicTargetAuthorizationApprovalRequest(
                "integration-test-evidence",
                "separate-admin-approval",
                DateTimeOffset.UtcNow.AddHours(1)));
        Assert.Equal(HttpStatusCode.OK, approvalResponse.StatusCode);

        var assessmentRequest = new CreateWebAssessmentRequest(
            "In-process worker integration assessment",
            "https://example.com/",
            WebHostingMode.Public,
            null,
            WebAssessmentOperationProfiles.Passive,
            [],
            10,
            60,
            "integration-test-evidence",
            DateTimeOffset.UtcNow.AddMinutes(10),
            PublicTargetAuthorizationIds: [authorization.Id]);

        var createResponse = await requesterClient.PostAsJsonAsync("/api/v1/web-assessments", assessmentRequest);
        Assert.Equal(HttpStatusCode.Accepted, createResponse.StatusCode);
        var created = await createResponse.Content.ReadFromJsonAsync<WebAssessmentResponse>();
        Assert.NotNull(created);

        var executionSignal = await Task.WhenAny(probe.Executed.Task, Task.Delay(TimeSpan.FromSeconds(10)));
        Assert.Same(probe.Executed.Task, executionSignal);
        var execution = await probe.Executed.Task;
        Assert.Equal("in-process", execution.WorkerIdentity);
        Assert.Contains(WebAssessmentCapabilities.WebAssessment, execution.WorkerCapabilities);
        Assert.True(execution.LeaseWasValid);
        Assert.True(execution.LiveAuthorizationWasValid);

        WebAssessmentResponse? final = null;
        for (var attempt = 0; attempt < 50; attempt++)
        {
            var response = await requesterClient.GetAsync($"/api/v1/web-assessments/{created.Id}");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            final = await response.Content.ReadFromJsonAsync<WebAssessmentResponse>();
            if (final?.Status is WebAssessmentStatus.Completed or WebAssessmentStatus.Failed) break;
            await Task.Delay(100);
        }

        Assert.NotNull(final);
        Assert.Equal(WebAssessmentStatus.Completed, final.Status);
        Assert.Equal(ScanJobStatus.Completed, final.JobStatus);

        var workers = await requesterClient.GetFromJsonAsync<List<WorkerResponse>>("/api/v1/workers");
        Assert.NotNull(workers);
        var localWorker = Assert.Single(workers, worker => worker.Identity == "in-process");
        Assert.Equal(WorkerStatus.Healthy, localWorker.Status);
        Assert.Contains(WebAssessmentCapabilities.WebAssessment, localWorker.Capabilities);
        Assert.DoesNotContain(WebAssessmentCapabilities.PrivateWebAssessment, localWorker.Capabilities);
    }

    private sealed class ProviderHealthHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"data\":[]}", System.Text.Encoding.UTF8, "application/json")
            });
    }

    private static HttpClient CreateAuthenticatedClient(
        WebApplicationFactory<Program> application,
        Guid tenant,
        Guid user,
        UserRole role)
    {
        var client = application.CreateClient();
        client.DefaultRequestHeaders.Add("X-Tenant-Id", tenant.ToString());
        client.DefaultRequestHeaders.Add("X-User-Id", user.ToString());
        client.DefaultRequestHeaders.Add("X-Role", role.ToString());
        return client;
    }

    public sealed class InProcessWorkerProbe
    {
        public TaskCompletionSource<InProcessWorkerExecution> Executed { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    public sealed record InProcessWorkerExecution(
        string WorkerIdentity,
        IReadOnlyCollection<string> WorkerCapabilities,
        bool LeaseWasValid,
        bool LiveAuthorizationWasValid);

    public sealed class InProcessWorkerProbeEngine(InProcessWorkerProbe probe, IServiceScopeFactory scopeFactory) : IWebAssessmentEngine
    {
        public async Task<WebAssessmentExecutionResult> ExecuteAsync(
            WebAssessment assessment,
            AgentJob job,
            TargetScope scope,
            string workerIdentity,
            IReadOnlyCollection<string> workerCapabilities,
            IReadOnlyCollection<string>? approvedPrivateNetworkRanges,
            Func<IAppDbContext, CancellationToken, Task<bool>> leaseCheck,
            CancellationToken cancellationToken,
            Func<IAppDbContext, CancellationToken, Task<WorkerExecutionContext?>>? refreshAuthorization = null)
        {
            await using var serviceScope = scopeFactory.CreateAsyncScope();
            var db = serviceScope.ServiceProvider.GetRequiredService<IAppDbContext>();
            var leaseIsValid = await leaseCheck(db, cancellationToken);
            var liveWorker = refreshAuthorization is null ? null : await refreshAuthorization(db, cancellationToken);

            probe.Executed.TrySetResult(new InProcessWorkerExecution(
                workerIdentity,
                workerCapabilities,
                leaseIsValid,
                liveWorker is not null));
            return new WebAssessmentExecutionResult("integration-test/report.html", 0);
        }
    }

    public sealed class FixedPublicAddressResolver : IHostAddressResolver
    {
        private static readonly IReadOnlyCollection<IPAddress> Addresses = [IPAddress.Parse("93.184.216.34")];

        public Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
            => Task.FromResult(Addresses);
    }


    private sealed class ReportRouteGenerator(ReportRouteArtifactStore artifacts) : IHtmlReportGenerator
    {
        public int CallCount { get; private set; }
        public bool LastIncludeAdvisorySummaries { get; private set; }

        public async Task<string> GenerateAsync(Guid tenantId, WebAssessment assessment, TargetScope scope,
            CancellationToken cancellationToken, bool includeAdvisoryAiSummaries = false)
        {
            CallCount++;
            LastIncludeAdvisorySummaries = includeAdvisoryAiSummaries;
            var html = includeAdvisoryAiSummaries
                ? "<h1>AI advisory summary · Human review required</h1>"
                : "<h1>Default report generated by the test fixture</h1>";
            return await artifacts.StageReportAsync(tenantId, assessment.Id,
                System.Text.Encoding.UTF8.GetBytes(html), cancellationToken);
        }
    }

    private sealed class ReportRouteArtifactStore : IAssessmentArtifactStore
    {
        private readonly Dictionary<string, byte[]> published = new(StringComparer.Ordinal);
        private readonly Dictionary<string, byte[]> staged = new(StringComparer.Ordinal);
        public string? LastPublishedKey { get; private set; }
        public HashSet<string> DiscardedKeys { get; } = new(StringComparer.Ordinal);

        public void SeedPublished(Guid tenantId, Guid assessmentId, string key, string content)
            => published[Key(tenantId, assessmentId, key)] = System.Text.Encoding.UTF8.GetBytes(content);

        public byte[]? GetPublished(Guid tenantId, Guid assessmentId, string? key)
            => key is null || !published.TryGetValue(Key(tenantId, assessmentId, key), out var content)
                ? null
                : content;

        public Task<string> PutAsync(Guid tenantId, Guid assessmentId, string name, byte[] content,
            CancellationToken cancellationToken)
        {
            var key = Key(tenantId, assessmentId, name);
            published[key] = content.ToArray();
            return Task.FromResult(key);
        }

        public Task<byte[]?> GetAsync(Guid tenantId, string storageKey, CancellationToken cancellationToken)
            => Task.FromResult(published.TryGetValue(storageKey, out var content) ? content.ToArray() : null);

        public Task<string> StageReportAsync(Guid tenantId, Guid assessmentId, byte[] content,
            CancellationToken cancellationToken)
        {
            var key = Key(tenantId, assessmentId, $".staging/{Guid.NewGuid():N}.html");
            staged[key] = content.ToArray();
            return Task.FromResult(key);
        }

        public Task<string> PublishReportAsync(Guid tenantId, Guid assessmentId, string stagingKey,
            CancellationToken cancellationToken)
        {
            if (!staged.Remove(stagingKey, out var content))
                throw new InvalidOperationException("The staged report does not exist.");
            var key = Key(tenantId, assessmentId, $"reports/{Guid.NewGuid():N}.html");
            published[key] = content;
            LastPublishedKey = key;
            return Task.FromResult(key);
        }

        public Task<byte[]?> GetPublishedReportAsync(Guid tenantId, Guid assessmentId, string storageKey,
            CancellationToken cancellationToken)
            => Task.FromResult(published.TryGetValue(Key(tenantId, assessmentId, storageKey), out var content)
                ? content.ToArray()
                : null);

        public Task DiscardReportAsync(Guid tenantId, Guid assessmentId, string storageKey,
            CancellationToken cancellationToken)
        {
            var key = Key(tenantId, assessmentId, storageKey);
            staged.Remove(key);
            published.Remove(key);
            DiscardedKeys.Add(storageKey);
            return Task.CompletedTask;
        }

        public Task<int> CleanupStagedReportsAsync(DateTimeOffset olderThan, CancellationToken cancellationToken)
            => Task.FromResult(0);

        public Task<int> ReconcilePublishedReportsAsync(DateTimeOffset olderThan,
            Func<string, Task<bool>> isReferencedAsync, CancellationToken cancellationToken)
            => Task.FromResult(0);

        private static string Key(Guid tenantId, Guid assessmentId, string storageKey)
        {
            var prefix = $"{tenantId:N}/{assessmentId:N}/";
            return storageKey.StartsWith(prefix, StringComparison.Ordinal) ? storageKey : prefix + storageKey;
        }
    }

    private sealed class IntegrationFakeProvider : IAIProvider
    {
        public string Name => "test";
        public bool IsConfigured => true;
        public int CallCount { get; private set; }

        public Task<AIResponse> AnalyzeAsync(AIRequest request, CancellationToken cancellationToken = default)
        {
            CallCount++;
            Assert.Contains("untrusted data", request.SystemPrompt, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("evidence", request.UserPrompt, StringComparison.OrdinalIgnoreCase);
            Assert.NotNull(request.JsonSchemaJson);
            var result = JsonSerializer.Serialize(new FindingAIAnalysisResultResponse(
                "The stored evidence supports analyst review.",
                "The evidence indicates a potential security posture gap.",
                "Medium",
                [],
                ["Browser and runtime behavior were not independently verified."]));
            return Task.FromResult(new AIResponse(Name, "integration-test-model", result,
                18, 7, "api-integration-response", "stop", true));
        }

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(true);
    }

    private HttpClient CreateAuthenticatedClient(Guid tenant, Guid user, UserRole role)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Tenant-Id", tenant.ToString());
        client.DefaultRequestHeaders.Add("X-User-Id", user.ToString());
        client.DefaultRequestHeaders.Add("X-Role", role.ToString());
        return client;
    }

    private async Task SeedInventoryAsync(Guid tenant, Guid otherTenant)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var tenantScope = new TargetScope(tenant, "seeded-inventory", userId, DateTimeOffset.UtcNow.AddHours(1));
        var otherScope = new TargetScope(otherTenant, "other-inventory", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        var asset = new Asset(tenant, tenantScope.Id, "10.10.0.5", TargetKind.Network);
        asset.RecordReachabilityConfirmation();
        db.AddRange(tenantScope, otherScope, asset, new AssetService(tenant, asset.Id, "https", 443, "test-service", "1.0"), new Finding(tenant, asset.Id, "Seeded finding", FindingSeverity.High), new Asset(otherTenant, otherScope.Id, "10.20.0.5", TargetKind.Network));
        await db.SaveChangesAsync();
    }
}
