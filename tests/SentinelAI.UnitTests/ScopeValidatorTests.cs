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

    [Fact]
    public void IPv6_unique_local_scope_is_accepted()
    {
        var scope = CreateScope("fd12:3456::/48", DateTimeOffset.UtcNow.AddHours(1));
        var result = validator.ValidateDefinition(scope, tenantId, DateTimeOffset.UtcNow);
        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData("10.0.0.0/8")]
    [InlineData("172.16.0.0/12")]
    [InlineData("192.168.0.0/16")]
    [InlineData("fd00::/8")]
    public void Administrator_private_ranges_must_be_entirely_private(string range)
        => Assert.True(TargetScopeValidator.IsValidPrivateNetworkRange(range));

    [Theory]
    [InlineData("10.0.0.0/7")]
    [InlineData("192.168.0.0/15")]
    [InlineData("::ffff:10.0.0.0/104")]
    [InlineData("169.254.0.0/16")]
    public void Mixed_or_special_private_ranges_are_rejected(string range)
        => Assert.False(TargetScopeValidator.IsValidPrivateNetworkRange(range));

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.1.1")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("ff02::1")]
    [InlineData("2001:db8::1")]
    public void Special_purpose_addresses_are_rejected(string target)
    {
        var scope = CreateScope(target, DateTimeOffset.UtcNow.AddHours(1));
        var result = validator.ValidateDefinition(scope, tenantId, DateTimeOffset.UtcNow);
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Cidr_exclusion_matches_an_address_inside_the_range()
    {
        var scope = CreateScope("10.20.0.0/16", DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.20.0.0/16")], ["10.20.10.0/24"], ["mock-passive"], 30, 300, "ticket-123", false);
        var result = await validator.ValidateExecutionAsync(scope, tenantId, "10.20.10.4", "mock-passive");
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("excluded", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Cidr_exclusion_boundaries_allow_only_addresses_outside_the_excluded_range()
    {
        var scope = CreateScope("10.40.0.0/24", DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Network, "10.40.0.0/24")], ["10.40.0.128/25"], ["mock-passive"], 30, 300, "ticket-123", false);

        var lowerBoundary = await validator.ValidateExecutionAsync(scope, tenantId, "10.40.0.127", "mock-passive");
        var upperBoundary = await validator.ValidateExecutionAsync(scope, tenantId, "10.40.0.128", "mock-passive");
        var lastAddress = await validator.ValidateExecutionAsync(scope, tenantId, "10.40.0.255", "mock-passive");

        Assert.True(lowerBoundary.IsValid);
        Assert.False(upperBoundary.IsValid);
        Assert.False(lastAddress.IsValid);
        Assert.Contains(upperBoundary.Errors, error => error.Contains("excluded", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Domain_matching_is_boundary_aware_and_dns_rebinding_is_rejected()
    {
        var scope = new TargetScope(tenantId, "public-web", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Web, "https://example.com")], [], ["web-passive"], 30, 300, "ticket-123", false);
        scope.ConfigureVerifications([new PublicTargetVerification("https://example.com", "ticket-123", "security", "registry", DateTimeOffset.UtcNow)]);
        var boundary = await new TargetScopeValidator(new RebindingResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://notexample.com", "web-passive");
        var rebinding = await new TargetScopeValidator(new RebindingResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://example.com", "web-passive");
        Assert.False(boundary.IsValid);
        Assert.False(rebinding.IsValid);
    }

    [Fact]
    public void Public_authorization_does_not_cross_port_or_sibling_path_boundaries()
    {
        var scope = new TargetScope(tenantId, "public-web", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Web, "https://example.com/app")], [], ["web-passive"], 30, 300, "ticket", false);
        scope.ConfigureVerifications([new PublicTargetVerification("https://example.com/app", "ticket", "admin", "review", DateTimeOffset.UtcNow)]);

        var portScope = new TargetScope(tenantId, "wrong-port", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        portScope.Configure([new TargetDefinition(TargetKind.Web, "https://example.com:8443/app")], [], ["web-passive"], 30, 300, "ticket", false);
        portScope.ConfigureVerifications([new PublicTargetVerification("https://example.com/app", "ticket", "admin", "review", DateTimeOffset.UtcNow)]);

        var siblingScope = new TargetScope(tenantId, "sibling", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        siblingScope.Configure([new TargetDefinition(TargetKind.Web, "https://example.com/application")], [], ["web-passive"], 30, 300, "ticket", false);
        siblingScope.ConfigureVerifications([new PublicTargetVerification("https://example.com/app", "ticket", "admin", "review", DateTimeOffset.UtcNow)]);

        Assert.True(validator.ValidateDefinition(scope, tenantId, DateTimeOffset.UtcNow).IsValid);
        Assert.False(validator.ValidateDefinition(portScope, tenantId, DateTimeOffset.UtcNow).IsValid);
        Assert.False(validator.ValidateDefinition(siblingScope, tenantId, DateTimeOffset.UtcNow).IsValid);
    }

    [Fact]
    public void Web_assessment_execution_time_cannot_exceed_ten_minutes()
    {
        var scope = new TargetScope(tenantId, "bounded-web-timeout", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Web, "https://private.example.test")], [],
            ["web-assessment-passive"], 30, 601, "approved-test-scope", false);
        scope.ConfigureWebHosting(WebHostingMode.Private, "worker-a", ["10.20.0.0/16"]);

        var result = validator.ValidateDefinition(scope, tenantId, DateTimeOffset.UtcNow);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("600 seconds", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Private_execution_requires_the_intersection_of_scope_and_worker_ranges()
    {
        var scope = new TargetScope(tenantId, "private-web", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Web, "https://private.example.test")], [], ["web-assessment-passive"], 30, 300, "approved", false);
        scope.ConfigureWebHosting(WebHostingMode.Private, "worker-a", ["10.20.0.0/16"]);
        var allowed = await new TargetScopeValidator(new PrivateResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://private.example.test", "web-assessment-passive", new WorkerExecutionContext("worker-a", ["web-assessment", "private-web-assessment"], ["10.20.10.0/24"]));
        var outside = await new TargetScopeValidator(new OutsidePrivateResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://private.example.test", "web-assessment-passive", new WorkerExecutionContext("worker-a", ["web-assessment", "private-web-assessment"], ["10.20.10.0/24"]));
        Assert.True(allowed.IsValid);
        Assert.False(outside.IsValid);
    }

    [Fact]
    public async Task Production_web_scope_enforces_scheme_effective_port_host_and_path_boundaries()
    {
        var scope = CreatePublicWebScope("https://example.com/app", allowSubdomains: true);

        Assert.True((await new TargetScopeValidator(new PublicResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://example.com/app/dashboard", "web-assessment-passive")).IsValid);
        Assert.True((await new TargetScopeValidator(new PublicResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://example.com/app/", "web-assessment-passive")).IsValid);
        Assert.True((await new TargetScopeValidator(new PublicResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://example.com/app/assets/site.css?theme=dark#main", "web-assessment-passive")).IsValid);
        Assert.True((await new TargetScopeValidator(new PublicResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://example.com:443/app/assets/site.css", "web-assessment-passive")).IsValid);
        Assert.True((await new TargetScopeValidator(new PublicResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://sub.example.com/app", "web-assessment-passive")).IsValid);
        Assert.False((await new TargetScopeValidator(new PublicResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "http://example.com/app", "web-assessment-passive")).IsValid);
        Assert.False((await new TargetScopeValidator(new PublicResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://notexample.com/app", "web-assessment-passive")).IsValid);
        Assert.False((await new TargetScopeValidator(new PublicResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://example.com:8443/app", "web-assessment-passive")).IsValid);
        Assert.False((await new TargetScopeValidator(new PublicResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://example.com/application", "web-assessment-passive")).IsValid);
        Assert.False((await new TargetScopeValidator(new PublicResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://example.com/app2", "web-assessment-passive")).IsValid);
        Assert.False((await new TargetScopeValidator(new PublicResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://example.com/outside", "web-assessment-passive")).IsValid);
        Assert.False((await new TargetScopeValidator(new PublicResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://user:password@example.com/app", "web-assessment-passive")).IsValid);
    }

    [Theory]
    [InlineData("https://example.com/app/../admin")]
    [InlineData("https://example.com/app/%2e%2e/admin")]
    [InlineData("https://example.com/app/%2E%2E/admin")]
    [InlineData("https://example.com/app/%252e%252e/admin")]
    [InlineData("https://example.com/app/%2fadmin")]
    [InlineData("https://example.com/app/%5cadmin")]
    [InlineData("https://example.com/app//admin")]
    public async Task Production_web_scope_rejects_ambiguous_or_traversal_paths(string target)
    {
        var scope = CreatePublicWebScope("https://example.com/app");
        var result = await new TargetScopeValidator(new PublicResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, target, "web-assessment-passive");
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Production_web_scope_applies_dns_and_path_exclusions_at_execution_time()
    {
        var scope = CreatePublicWebScope("https://example.com/app");
        scope.Configure([new TargetDefinition(TargetKind.Web, "https://example.com/app")], ["https://example.com/app/admin", "evil.example.com"], ["web-assessment-passive"], 30, 300, "ticket-123", false);
        scope.ConfigureVerifications([new PublicTargetVerification("https://example.com/app", "ticket-123", "security", "registry", DateTimeOffset.UtcNow)]);

        var excludedPath = await new TargetScopeValidator(new PublicResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://example.com/app/admin", "web-assessment-passive");
        var excludedSubdomain = await new TargetScopeValidator(new PublicResolver()).ValidateExecutionAsync(scope, tenantId, TargetKind.Web, "https://evil.example.com/app", "web-assessment-passive");

        Assert.False(excludedPath.IsValid);
        Assert.False(excludedSubdomain.IsValid);
    }

    private TargetScope CreateScope(string target, DateTimeOffset expiresAt)
    {
        var scope = new TargetScope(tenantId, "test-scope", Guid.NewGuid(), expiresAt);
        scope.Configure([new TargetDefinition(TargetKind.Network, target)], [], ["mock-passive"], 30, 300, "ticket-123", false);
        return scope;
    }

    private TargetScope CreatePublicWebScope(string target, bool allowSubdomains = false)
    {
        var scope = new TargetScope(tenantId, "public-web", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        scope.Configure([new TargetDefinition(TargetKind.Web, target)], [], ["web-assessment-passive"], 30, 300, "ticket-123", publicTargetOwnershipVerified: false, allowSubdomains: allowSubdomains);
        scope.ConfigureVerifications([new PublicTargetVerification(target, "ticket-123", "security", "registry", DateTimeOffset.UtcNow)]);
        return scope;
    }

    private sealed class StubResolver : IHostAddressResolver
    {
        public Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyCollection<IPAddress>>([IPAddress.Parse("10.20.1.2")]);
    }

    private sealed class RebindingResolver : IHostAddressResolver
    {
        public Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyCollection<IPAddress>>([IPAddress.Parse("10.0.0.4")]);
    }

    private sealed class PrivateResolver : IHostAddressResolver
    { public Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyCollection<IPAddress>>([IPAddress.Parse("10.20.10.4")]); }
    private sealed class OutsidePrivateResolver : IHostAddressResolver
    { public Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyCollection<IPAddress>>([IPAddress.Parse("10.21.10.4")]); }
    private sealed class PublicResolver : IHostAddressResolver
    { public Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyCollection<IPAddress>>([IPAddress.Parse("93.184.216.34")]); }
}
