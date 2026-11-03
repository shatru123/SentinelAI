using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Contracts;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;

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
