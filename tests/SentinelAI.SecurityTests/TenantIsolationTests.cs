using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;
using SentinelAI.Security.Policy;
using System.Net;

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

    [Fact]
    public void Mixed_cidr_ranges_require_full_range_authorization()
    {
        var tenant = Guid.NewGuid();
        var scope = new TargetScope(tenant, "mixed", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/7")], [], ["mock-passive"], 10, 120, "ticket", false);

        var result = new TargetScopeValidator(new StaticResolver([])).ValidateDefinition(scope, tenant, DateTimeOffset.UtcNow);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("authorization", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Network_range_intersecting_reserved_space_is_rejected()
    {
        var tenant = Guid.NewGuid();
        var scope = new TargetScope(tenant, "reserved", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "192.0.0.0/15")], [], ["mock-passive"], 10, 120, "ticket", false);

        var result = new TargetScopeValidator(new StaticResolver([])).ValidateDefinition(scope, tenant, DateTimeOffset.UtcNow);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("special-purpose", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Dns_exclusion_is_applied_to_every_resolved_address()
    {
        var tenant = Guid.NewGuid();
        var scope = new TargetScope(tenant, "dns", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.0.0.0/8")], ["10.0.0.0/24"], ["mock-passive"], 10, 120, "ticket", false);
        var validator = new TargetScopeValidator(new StaticResolver([IPAddress.Parse("10.0.0.10"), IPAddress.Parse("10.1.0.10")]));

        var result = await validator.ValidateExecutionAsync(scope, tenant, TargetKind.Network, "lab.example", "mock-passive");

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("excluded", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Web_subdomains_require_an_explicit_scope_option()
    {
        var tenant = Guid.NewGuid();
        var scope = new TargetScope(tenant, "web", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Web, "https://example.com")], [], ["web-passive"], 10, 120, "ticket", false);
        scope.ConfigureVerifications([new PublicTargetVerification("https://example.com", "ticket", "admin", "manual", DateTimeOffset.UtcNow)]);
        var validator = new TargetScopeValidator(new StaticResolver([IPAddress.Parse("93.184.216.34")]));

        var denied = await validator.ValidateExecutionAsync(scope, tenant, TargetKind.Web, "https://sub.example.com", "web-passive");
        scope.Configure([new TargetDefinition(TargetKind.Web, "https://example.com")], [], ["web-passive"], 10, 120, "ticket", false, true);
        var allowed = await validator.ValidateExecutionAsync(scope, tenant, TargetKind.Web, "https://sub.example.com", "web-passive");

        Assert.False(denied.IsValid);
        Assert.True(allowed.IsValid);
    }

    private sealed class StaticResolver(IReadOnlyCollection<IPAddress> addresses) : IHostAddressResolver
    {
        public Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(addresses);
    }
}
