using System.Net;
using SentinelAI.Domain;
using SentinelAI.Security.Policy;

namespace SentinelAI.UnitTests;

public sealed class ScopeValidatorTests
{
    private readonly TargetScopeValidator validator = new(new StubResolver());
    private readonly Guid tenantId = Guid.NewGuid();

    [Fact]
    public void Valid_private_cidr_is_accepted()
    {
        var scope = CreateScope("10.20.0.0/16", DateTimeOffset.UtcNow.AddHours(1));
        var result = validator.ValidateDefinition(scope, tenantId, DateTimeOffset.UtcNow);
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Expired_scope_is_rejected()
    {
        var scope = CreateScope("10.20.0.0/16", DateTimeOffset.UtcNow.AddMinutes(-1));
        var result = validator.ValidateDefinition(scope, tenantId, DateTimeOffset.UtcNow);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("expired", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Public_scope_requires_ownership_verification()
    {
        var scope = CreateScope("8.8.8.8", DateTimeOffset.UtcNow.AddHours(1));
        var result = validator.ValidateDefinition(scope, tenantId, DateTimeOffset.UtcNow);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("ownership", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Execution_outside_scope_is_rejected()
    {
        var scope = CreateScope("10.20.0.0/16", DateTimeOffset.UtcNow.AddHours(1));
        var result = await validator.ValidateExecutionAsync(scope, tenantId, "10.21.1.4", "mock-passive");
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("outside", StringComparison.OrdinalIgnoreCase));
    }

    private TargetScope CreateScope(string target, DateTimeOffset expiresAt)
    {
        var scope = new TargetScope(tenantId, "test-scope", Guid.NewGuid(), expiresAt);
        scope.Configure([new TargetDefinition(TargetKind.Network, target)], [], ["mock-passive"], 30, 300, "ticket-123", false);
        return scope;
    }

    private sealed class StubResolver : IHostAddressResolver
    {
        public Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyCollection<IPAddress>>([IPAddress.Parse("10.20.1.2")]);
    }
}
