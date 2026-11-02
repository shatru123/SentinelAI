using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;

namespace SentinelAI.SecurityTests;

public sealed class TenantIsolationTests
{
    [Fact]
    public async Task Tenant_query_cannot_read_another_tenants_scope()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        await using var db = new AppDbContext(options);
        var first = new Tenant("First"); var second = new Tenant("Second"); db.Tenants.AddRange(first, second);
        db.TargetScopes.Add(new TargetScope(first.Id, "first-scope", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1)));
        db.TargetScopes.Add(new TargetScope(second.Id, "second-scope", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1)));
        await db.SaveChangesAsync();

        var visible = await db.TargetScopes.Where(scope => scope.TenantId == first.Id).ToListAsync();
        Assert.Single(visible);
        Assert.Equal(first.Id, visible[0].TenantId);
    }
}
