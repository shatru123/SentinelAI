using Microsoft.Extensions.Configuration;
using SentinelAI.Infrastructure;

namespace SentinelAI.UnitTests;

public sealed class AssessmentArtifactStoreTests
{
    [Fact]
    public async Task Staged_report_is_not_retrievable_until_published_and_tenant_assessment_boundaries_hold()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-artifacts-{Guid.NewGuid():N}");
        var tenantA = Guid.NewGuid();
        var tenantB = Guid.NewGuid();
        var assessmentA = Guid.NewGuid();
        var assessmentB = Guid.NewGuid();
        try
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Artifacts:Root"] = root }).Build();
            var store = new FileSystemAssessmentArtifactStore(configuration);
            var bytes = new byte[] { 60, 104, 49, 62 };

            var staged = await store.StageReportAsync(tenantA, assessmentA, bytes, CancellationToken.None);
            Assert.Null(await store.GetPublishedReportAsync(tenantA, assessmentA, staged, CancellationToken.None));
            Assert.Null(await store.GetAsync(tenantA, staged, CancellationToken.None));

            var published = await store.PublishReportAsync(tenantA, assessmentA, staged, CancellationToken.None);
            Assert.Equal(bytes, await store.GetPublishedReportAsync(tenantA, assessmentA, published, CancellationToken.None));
            Assert.Null(await store.GetPublishedReportAsync(tenantB, assessmentA, published, CancellationToken.None));
            Assert.Null(await store.GetPublishedReportAsync(tenantA, assessmentB, published, CancellationToken.None));
            Assert.Null(await store.GetPublishedReportAsync(tenantA, assessmentA, staged, CancellationToken.None));

            await store.DiscardReportAsync(tenantA, assessmentA, published, CancellationToken.None);
            Assert.Null(await store.GetPublishedReportAsync(tenantA, assessmentA, published, CancellationToken.None));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Abandoned_staged_reports_are_bounded_and_cleaned_without_touching_published_reports()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-artifacts-{Guid.NewGuid():N}");
        var tenant = Guid.NewGuid();
        var assessment = Guid.NewGuid();
        try
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Artifacts:Root"] = root }).Build();
            var store = new FileSystemAssessmentArtifactStore(configuration);
            var oldStaged = await store.StageReportAsync(tenant, assessment, [1, 2, 3], CancellationToken.None);
            var publishedStaged = await store.StageReportAsync(tenant, assessment, [4, 5, 6], CancellationToken.None);
            var published = await store.PublishReportAsync(tenant, assessment, publishedStaged, CancellationToken.None);
            File.SetLastWriteTimeUtc(Path.Combine(root, oldStaged.Replace('/', Path.DirectorySeparatorChar)), DateTime.UtcNow.AddHours(-2));

            var removed = await store.CleanupStagedReportsAsync(DateTimeOffset.UtcNow.AddHours(-1), CancellationToken.None);

            Assert.Equal(1, removed);
            Assert.Null(await store.GetPublishedReportAsync(tenant, assessment, oldStaged, CancellationToken.None));
            Assert.Equal(new byte[] { 4, 5, 6 }, await store.GetPublishedReportAsync(tenant, assessment, published, CancellationToken.None));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
