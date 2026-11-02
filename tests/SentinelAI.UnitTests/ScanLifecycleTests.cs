using Microsoft.EntityFrameworkCore;
using SentinelAI.Application;
using SentinelAI.Contracts;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;
using SentinelAI.Security.Policy;

namespace SentinelAI.UnitTests;

public sealed class ScanLifecycleTests
{
    [Fact]
    public async Task Authorized_scan_is_persisted_and_queued()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        await using var db = new AppDbContext(options);
        var tenant = new Tenant("Test tenant"); db.Tenants.Add(tenant);
        var user = new User(tenant.Id, "analyst", "Analyst", UserRole.SecurityAnalyst); db.Users.Add(user);
        var scope = new TargetScope(tenant.Id, "private-lab", user.Id, DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], [], ["mock-passive"], 10, 120, "approval-1", false); db.TargetScopes.Add(scope);
        await db.SaveChangesAsync();
        var queue = new InMemoryScanJobQueue();
        var service = new ScanService(db, new TargetScopeValidator(new StubResolver()), queue);

        var result = await service.CreateAsync(new PrincipalContext(tenant.Id, user.Id, user.Subject, user.Role), new CreateScanRequest(scope.Id, "mock-passive"), CancellationToken.None);

        Assert.Equal(ScanJobStatus.Queued, result.Status);
        Assert.Single(await db.AgentJobs.ToListAsync());
        Assert.Equal(result.Id, await queue.ReadAllAsync().FirstAsync());
    }

    private sealed class StubResolver : IHostAddressResolver
    {
        public Task<IReadOnlyCollection<System.Net.IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyCollection<System.Net.IPAddress>>([]);
    }
}
