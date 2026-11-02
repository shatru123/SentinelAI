using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SentinelAI.Application;
using SentinelAI.Contracts;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;
using SentinelAI.Worker;

namespace SentinelAI.IntegrationTests;

public sealed class PassiveInventoryWorkflowTests
{
    [Fact]
    public async Task Authorized_scan_traverses_outbox_rabbit_worker_postgres_and_tenant_scoped_assets_api()
    {
        var tenantId = Guid.NewGuid();
        var operatorId = Guid.NewGuid();
        var workerId = $"phase21-worker-{Guid.NewGuid():N}";
        using var factory = CreateApiFactory();
        using var operatorClient = factory.CreateClient();
        AddIdentity(operatorClient, tenantId, operatorId, UserRole.SecurityAnalyst);
        using var workerRegistrationClient = factory.CreateClient();
        AddIdentity(workerRegistrationClient, tenantId, Guid.NewGuid(), UserRole.Worker, workerId);

        var registration = await workerRegistrationClient.PostAsJsonAsync("/api/v1/workers/register", new WorkerRegistrationRequest(workerId, "phase2.1-test", ["passive-inventory", "cancellation"], 1));
        Assert.Equal(HttpStatusCode.OK, registration.StatusCode);
        var registeredWorker = await registration.Content.ReadFromJsonAsync<WorkerResponse>();
        Assert.NotNull(registeredWorker);
        Assert.Contains("passive-inventory", registeredWorker.Capabilities);

        var scopeRequest = new CreateScopeRequest(
            "phase21-private-lab",
            [new TargetDefinition(TargetKind.Network, "10.40.0.5")],
            ["10.40.0.0/30"],
            [InventoryOperationProfiles.NetworkInventoryPassive],
            1,
            120,
            "phase21-authorized-lab",
            DateTimeOffset.UtcNow.AddMinutes(10));
        var scopeResponse = await operatorClient.PostAsJsonAsync("/api/v1/scopes", scopeRequest);
        Assert.Equal(HttpStatusCode.Created, scopeResponse.StatusCode);
        var scope = await scopeResponse.Content.ReadFromJsonAsync<ScopeResponse>();
        Assert.NotNull(scope);

        using var workerHost = CreateWorkerHost(tenantId, workerId);
        await workerHost.StartAsync();
        try
        {
            var scanResponse = await operatorClient.PostAsJsonAsync("/api/v1/scans", new CreateScanRequest(scope!.Id, InventoryOperationProfiles.NetworkInventoryPassive));
            Assert.Equal(HttpStatusCode.Accepted, scanResponse.StatusCode);
            var scan = await scanResponse.Content.ReadFromJsonAsync<ScanResponse>();
            Assert.NotNull(scan);

            ScanResponse? completed = null;
            for (var attempt = 0; attempt < 40; attempt++)
            {
                await Task.Delay(250);
                completed = await operatorClient.GetFromJsonAsync<ScanResponse>($"/api/v1/scans/{scan!.Id}");
                if (completed is not null && (completed.Status is ScanJobStatus.Completed or ScanJobStatus.Failed or ScanJobStatus.Cancelled or ScanJobStatus.Expired)) break;
            }

            Assert.NotNull(completed);
            Assert.Equal(ScanJobStatus.Completed, completed!.Status);
            var assets = await operatorClient.GetFromJsonAsync<PagedResponse<AssetResponse>>("/api/v1/assets?page=1&pageSize=25");
            Assert.NotNull(assets);
            var asset = Assert.Single(assets.Items, item => item.Address == "10.40.0.5");
            Assert.False(asset.IsOnline);
            Assert.Null(asset.LastSuccessfulReachabilityAt);

            var events = await operatorClient.GetFromJsonAsync<List<AuditEvent>>("/api/v1/monitoring/events");
            Assert.Contains(events!, audit => audit.Action == "scan.completed" && audit.ResourceId == scan.Id);

            using var otherTenantClient = factory.CreateClient();
            AddIdentity(otherTenantClient, Guid.NewGuid(), Guid.NewGuid(), UserRole.Viewer);
            var otherAssets = await otherTenantClient.GetFromJsonAsync<PagedResponse<AssetResponse>>("/api/v1/assets?page=1&pageSize=25");
            Assert.NotNull(otherAssets);
            Assert.DoesNotContain(otherAssets.Items, item => item.Id == asset.Id);
            Assert.Equal(HttpStatusCode.NotFound, (await otherTenantClient.GetAsync($"/api/v1/assets/{asset.Id}/services")).StatusCode);
        }
        finally
        {
            await workerHost.StopAsync();
        }
    }

    private static WebApplicationFactory<Program> CreateApiFactory()
    {
        var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("Database:Provider", "Postgres");
            builder.UseSetting("ConnectionStrings:SentinelAI", PostgresConnection());
            builder.UseSetting("Database:ApplyMigrations", "true");
            builder.UseSetting("Messaging:Mode", "RabbitMq");
            builder.UseSetting("Messaging:RunOutboxDispatcher", "true");
            ConfigureRabbitMq(builder);
        });
        return factory;
    }

    private static IHost CreateWorkerHost(Guid tenantId, string workerId)
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Database:Provider"] = "Postgres",
            ["ConnectionStrings:SentinelAI"] = PostgresConnection(),
            ["Messaging:Mode"] = "RabbitMq",
            ["Worker:TenantId"] = tenantId.ToString(),
            ["Worker:Identity"] = workerId,
            ["Worker:Concurrency"] = "1",
            ["Worker:ExecutionDelayMs"] = "1",
            ["Worker:ControlPlaneUrl"] = "",
            ["RabbitMQ:Host"] = RabbitValue("RABBITMQ_TEST_HOST", "localhost"),
            ["RabbitMQ:Port"] = RabbitValue("RABBITMQ_TEST_PORT", "5672"),
            ["RabbitMQ:Username"] = RabbitValue("RABBITMQ_TEST_USER", "sentinelai"),
            ["RabbitMQ:Password"] = RabbitValue("RABBITMQ_TEST_PASSWORD", "replace-with-local-dev-password")
        });
        builder.Services.AddSingleton<WorkerOptions>();
        builder.Services.AddSentinelInfrastructure(builder.Configuration, builder.Environment);
        builder.Services.AddHttpClient<WorkerControlPlaneClient>();
        builder.Services.AddHostedService<SentinelAI.Worker.Worker>();
        return builder.Build();
    }

    private static void AddIdentity(HttpClient client, Guid tenantId, Guid userId, UserRole role, string? workerId = null)
    {
        client.DefaultRequestHeaders.Add("X-Tenant-Id", tenantId.ToString());
        client.DefaultRequestHeaders.Add("X-User-Id", userId.ToString());
        client.DefaultRequestHeaders.Add("X-Role", role.ToString());
        if (workerId is not null) client.DefaultRequestHeaders.Add("X-Worker-Id", workerId);
    }

    private static void ConfigureRabbitMq(IWebHostBuilder builder)
    {
        builder.UseSetting("RabbitMQ:Host", RabbitValue("RABBITMQ_TEST_HOST", "localhost"));
        builder.UseSetting("RabbitMQ:Port", RabbitValue("RABBITMQ_TEST_PORT", "5672"));
        builder.UseSetting("RabbitMQ:Username", RabbitValue("RABBITMQ_TEST_USER", "sentinelai"));
        builder.UseSetting("RabbitMQ:Password", RabbitValue("RABBITMQ_TEST_PASSWORD", "replace-with-local-dev-password"));
        builder.UseSetting("RabbitMQ:RetryDelayMs", "100");
    }

    private static string PostgresConnection()
        => Environment.GetEnvironmentVariable("SENTINELAI_POSTGRES_CONNECTION")
            ?? "Host=localhost;Port=5432;Database=sentinelai;Username=sentinelai;Password=replace-with-local-dev-password";

    private static string RabbitValue(string variable, string fallback)
        => Environment.GetEnvironmentVariable(variable) ?? fallback;
}
