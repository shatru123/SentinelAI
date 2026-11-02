using System.Net;
using System.Net.Http.Json;
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

        var scope = new CreateScopeRequest("approved-public", [new TargetDefinition(TargetKind.Web, "https://example.com")], [], ["web-passive"], 30, 300, "ticket-123", DateTimeOffset.UtcNow.AddHours(1), false, null, [authorization.Id]);
        var createdScope = await client.PostAsJsonAsync("/api/v1/scopes", scope);
        Assert.Equal(HttpStatusCode.Created, createdScope.StatusCode);
    }

    [Fact]
    public async Task Worker_can_register_and_heartbeat_through_authenticated_endpoint()
    {
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Tenant-Id", tenantId.ToString());
        client.DefaultRequestHeaders.Add("X-User-Id", Guid.NewGuid().ToString());
        client.DefaultRequestHeaders.Add("X-Role", "Worker");
        client.DefaultRequestHeaders.Add("X-Worker-Id", "test-worker");
        var register = await client.PostAsJsonAsync("/api/v1/workers/register", new WorkerRegistrationRequest("test-worker", "test", ["passive-mock", "cancellation"]));
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);
        var worker = await register.Content.ReadFromJsonAsync<WorkerResponse>();
        Assert.NotNull(worker);
        Assert.Equal(WorkerStatus.Healthy, worker.Status);
        var heartbeat = await client.PostAsJsonAsync("/api/v1/workers/heartbeat", new WorkerHeartbeatRequest("test-worker", 0, 2));
        Assert.Equal(HttpStatusCode.OK, heartbeat.StatusCode);
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

        using var otherClient = CreateAuthenticatedClient(otherTenantId, Guid.NewGuid(), UserRole.Viewer);
        var otherAssets = await otherClient.GetFromJsonAsync<PagedResponse<AssetResponse>>("/api/v1/assets");
        var otherFindings = await otherClient.GetFromJsonAsync<PagedResponse<FindingResponse>>("/api/v1/findings");
        Assert.NotNull(otherAssets);
        Assert.NotNull(otherFindings);
        Assert.Single(otherAssets.Items);
        Assert.Equal("10.20.0.5", otherAssets.Items.Single().Address);
        Assert.Empty(otherFindings.Items);
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
        asset.MarkSeen(true);
        db.AddRange(tenantScope, otherScope, asset, new Finding(tenant, asset.Id, "Seeded finding", FindingSeverity.High), new Asset(otherTenant, otherScope.Id, "10.20.0.5", TargetKind.Network));
        await db.SaveChangesAsync();
    }
}
