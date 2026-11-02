namespace SentinelAI.ArchitectureTests;

public sealed class ProjectBoundaryTests
{
    [Fact]
    public void Domain_does_not_reference_infrastructure_or_api()
    {
        var references = typeof(SentinelAI.Domain.Tenant).Assembly.GetReferencedAssemblies().Select(x => x.Name).ToArray();
        Assert.DoesNotContain("SentinelAI.Infrastructure", references);
        Assert.DoesNotContain("SentinelAI.Api", references);
    }

    [Fact]
    public void Application_does_not_reference_api_or_web()
    {
        var references = typeof(SentinelAI.Application.ScanService).Assembly.GetReferencedAssemblies().Select(x => x.Name).ToArray();
        Assert.DoesNotContain("SentinelAI.Api", references);
        Assert.DoesNotContain("SentinelAI.Web", references);
    }
}
