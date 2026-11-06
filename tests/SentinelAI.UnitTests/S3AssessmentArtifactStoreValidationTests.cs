using Microsoft.Extensions.Configuration;
using SentinelAI.Infrastructure;

namespace SentinelAI.UnitTests;

public sealed class S3AssessmentArtifactStoreValidationTests
{
    [Fact]
    public async Task Reads_reject_cross_tenant_traversal_and_staging_keys_before_storage_access()
    {
        var tenant = Guid.NewGuid();
        var otherTenant = Guid.NewGuid();
        var assessment = Guid.NewGuid();
        var store = CreateStore();

        Assert.Null(await store.GetAsync(tenant, $"{otherTenant:D}/{assessment:D}/reports/report.html", CancellationToken.None));
        Assert.Null(await store.GetAsync(tenant, $"{tenant:D}/{assessment:D}/../other/report.html", CancellationToken.None));
        Assert.Null(await store.GetAsync(tenant, $"{tenant:D}/{assessment:D}/folder\\..\\report.html", CancellationToken.None));
        Assert.Null(await store.GetAsync(tenant, $"{tenant:D}/{assessment:D}/.staging/report.html", CancellationToken.None));
    }

    [Fact]
    public async Task Report_operations_reject_windows_separator_traversal_before_storage_access()
    {
        var tenant = Guid.NewGuid();
        var assessment = Guid.NewGuid();
        var store = CreateStore();
        var traversal = $"{tenant:D}/{assessment:D}/folder\\..\\other";
        var stagingKey = $"{traversal}/.staging/report.html";
        var publishedKey = $"{traversal}/reports/report.html";

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.PublishReportAsync(tenant, assessment, stagingKey, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.DiscardReportAsync(tenant, assessment, publishedKey, CancellationToken.None));
        Assert.Null(await store.GetPublishedReportAsync(tenant, assessment, publishedKey, CancellationToken.None));
    }

    [Fact]
    public async Task Upload_rejects_traversal_segments_after_normalizing_backslashes()
    {
        var tenant = Guid.NewGuid();
        var assessment = Guid.NewGuid();
        var store = CreateStore();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            store.PutAsync(tenant, assessment, "folder\\..\\report.html", [], CancellationToken.None));
    }

    [Fact]
    public async Task Report_operations_reject_wrong_tenant_and_assessment_ownership()
    {
        var tenant = Guid.NewGuid();
        var otherTenant = Guid.NewGuid();
        var assessment = Guid.NewGuid();
        var otherAssessment = Guid.NewGuid();
        var store = CreateStore();

        var foreignTenantKey = $"{otherTenant:D}/{assessment:D}/.staging/report.html";
        var foreignAssessmentKey = $"{tenant:D}/{otherAssessment:D}/.staging/report.html";

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.PublishReportAsync(tenant, assessment, foreignTenantKey, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.PublishReportAsync(tenant, assessment, foreignAssessmentKey, CancellationToken.None));
    }

    private static S3AssessmentArtifactStore CreateStore()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Artifacts:S3:Bucket"] = "sentinelai-tests",
            ["Artifacts:S3:ServerSideEncryption"] = "AES256"
        }).Build();

        // All tests assert that invalid keys are rejected before any SDK call.
        return new S3AssessmentArtifactStore(null!, configuration);
    }
}
