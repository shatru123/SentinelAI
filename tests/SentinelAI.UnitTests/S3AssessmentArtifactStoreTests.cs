using System.Net;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Configuration;
using Moq;
using SentinelAI.Infrastructure;

namespace SentinelAI.UnitTests;

public sealed class S3AssessmentArtifactStoreTests
{
    [Fact]
    public async Task Put_uploads_tenant_scoped_object_with_server_side_encryption_and_content_type()
    {
        var client = new Mock<IAmazonS3>(MockBehavior.Strict);
        PutObjectRequest? captured = null;
        client.Setup(x => x.PutObjectAsync(It.IsAny<PutObjectRequest>(), It.IsAny<CancellationToken>()))
            .Callback<PutObjectRequest, CancellationToken>((request, _) => captured = request)
            .ReturnsAsync(new PutObjectResponse());

        var tenant = Guid.NewGuid();
        var assessment = Guid.NewGuid();
        var kmsKey = "arn:aws:kms:ap-south-1:123456789012:key/test-key";
        var store = CreateStore(client.Object, "aws:kms", kmsKey);

        var key = await store.PutAsync(tenant, assessment, "reports/summary.html", [1, 2, 3], CancellationToken.None);

        Assert.Equal($"{tenant:D}/{assessment:D}/reports/summary.html", key);
        Assert.NotNull(captured);
        Assert.Equal("sentinelai-artifacts", captured.BucketName);
        Assert.Equal(key, captured.Key);
        Assert.Equal("text/html; charset=utf-8", captured.ContentType);
        Assert.Equal(ServerSideEncryptionMethod.AWSKMS, captured.ServerSideEncryptionMethod);
        Assert.Equal(kmsKey, captured.ServerSideEncryptionKeyManagementServiceKeyId);
        client.VerifyAll();
    }

    [Fact]
    public async Task Stage_and_publish_copy_to_reports_prefix_then_delete_staging_object()
    {
        var client = new Mock<IAmazonS3>(MockBehavior.Strict);
        CopyObjectRequest? copy = null;
        DeleteObjectRequest? delete = null;
        client.Setup(x => x.PutObjectAsync(It.IsAny<PutObjectRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PutObjectResponse());
        client.Setup(x => x.CopyObjectAsync(It.IsAny<CopyObjectRequest>(), It.IsAny<CancellationToken>()))
            .Callback<CopyObjectRequest, CancellationToken>((request, _) => copy = request)
            .ReturnsAsync(new CopyObjectResponse());
        client.Setup(x => x.DeleteObjectAsync(It.IsAny<DeleteObjectRequest>(), It.IsAny<CancellationToken>()))
            .Callback<DeleteObjectRequest, CancellationToken>((request, _) => delete = request)
            .ReturnsAsync(new DeleteObjectResponse());

        var tenant = Guid.NewGuid();
        var assessment = Guid.NewGuid();
        var store = CreateStore(client.Object, "AES256");

        var staged = await store.StageReportAsync(tenant, assessment, [10, 20, 30], CancellationToken.None);
        var published = await store.PublishReportAsync(tenant, assessment, staged, CancellationToken.None);

        Assert.StartsWith($"{tenant:D}/{assessment:D}/.staging/", staged, StringComparison.Ordinal);
        Assert.Equal($"{tenant:D}/{assessment:D}/reports/{Path.GetFileName(staged)}", published);
        Assert.NotNull(copy);
        Assert.Equal("sentinelai-artifacts", copy.SourceBucket);
        Assert.Equal(staged, copy.SourceKey);
        Assert.Equal("sentinelai-artifacts", copy.DestinationBucket);
        Assert.Equal(published, copy.DestinationKey);
        Assert.Equal(ServerSideEncryptionMethod.AES256, copy.ServerSideEncryptionMethod);
        Assert.NotNull(delete);
        Assert.Equal("sentinelai-artifacts", delete.BucketName);
        Assert.Equal(staged, delete.Key);
        client.VerifyAll();
    }

    [Fact]
    public async Task Reads_published_report_bytes_and_returns_null_for_missing_objects()
    {
        var client = new Mock<IAmazonS3>(MockBehavior.Strict);
        var tenant = Guid.NewGuid();
        var assessment = Guid.NewGuid();
        var key = $"{tenant:D}/{assessment:D}/reports/report.html";
        var expected = new byte[] { 60, 104, 49, 62 };

        client.Setup(x => x.GetObjectAsync(It.Is<GetObjectRequest>(r => r.Key == key), It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new GetObjectResponse { ResponseStream = new MemoryStream(expected) });
        client.Setup(x => x.GetObjectAsync(It.Is<GetObjectRequest>(r => r.Key.EndsWith("missing.html", StringComparison.Ordinal)), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new AmazonS3Exception("Object does not exist") { StatusCode = HttpStatusCode.NotFound });

        var store = CreateStore(client.Object, "AES256");

        Assert.Equal(expected, await store.GetPublishedReportAsync(tenant, assessment, key, CancellationToken.None));
        Assert.Null(await store.GetPublishedReportAsync(tenant, assessment,
            $"{tenant:D}/{assessment:D}/reports/missing.html", CancellationToken.None));
        client.VerifyAll();
    }

    [Fact]
    public async Task Cleanup_staged_reports_paginates_and_deletes_only_expired_staging_objects()
    {
        var client = new Mock<IAmazonS3>(MockBehavior.Strict);
        var tenant = Guid.NewGuid();
        var assessment = Guid.NewGuid();
        var oldStaging = $"{tenant:D}/{assessment:D}/.staging/old.html";
        var recentStaging = $"{tenant:D}/{assessment:D}/.staging/recent.html";
        var oldPublished = $"{tenant:D}/{assessment:D}/reports/old.html";
        var deleted = new List<DeleteObjectRequest>();
        var firstPage = new ListObjectsV2Response { IsTruncated = true, NextContinuationToken = "page-2" };
        firstPage.S3Objects.Add(new S3Object { Key = oldStaging, LastModified = DateTime.UtcNow.AddDays(-2) });
        var secondPage = new ListObjectsV2Response { IsTruncated = false };
        secondPage.S3Objects.Add(new S3Object { Key = recentStaging, LastModified = DateTime.UtcNow });
        secondPage.S3Objects.Add(new S3Object { Key = oldPublished, LastModified = DateTime.UtcNow.AddDays(-2) });

        client.SetupSequence(x => x.ListObjectsV2Async(It.IsAny<ListObjectsV2Request>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(firstPage)
            .ReturnsAsync(secondPage);
        client.Setup(x => x.DeleteObjectAsync(It.IsAny<DeleteObjectRequest>(), It.IsAny<CancellationToken>()))
            .Callback<DeleteObjectRequest, CancellationToken>((request, _) => deleted.Add(request))
            .ReturnsAsync(new DeleteObjectResponse());

        var store = CreateStore(client.Object, "AES256");
        var removed = await store.CleanupStagedReportsAsync(DateTimeOffset.UtcNow.AddHours(-1), CancellationToken.None);

        Assert.Equal(1, removed);
        Assert.Single(deleted);
        Assert.Equal(oldStaging, deleted[0].Key);
        client.Verify(x => x.ListObjectsV2Async(
            It.Is<ListObjectsV2Request>(request => request.ContinuationToken == "page-2"),
            It.IsAny<CancellationToken>()), Times.Once);
        client.VerifyAll();
    }

    [Fact]
    public async Task Reconciliation_deletes_only_old_unreferenced_published_reports()
    {
        var client = new Mock<IAmazonS3>(MockBehavior.Strict);
        var tenant = Guid.NewGuid();
        var assessment = Guid.NewGuid();
        var referenced = $"{tenant:D}/{assessment:D}/reports/referenced.html";
        var orphan = $"{tenant:D}/{assessment:D}/reports/orphan.html";
        var recent = $"{tenant:D}/{assessment:D}/reports/recent.html";
        var unrelated = $"{tenant:D}/{assessment:D}/screenshots/image.png";
        var deleted = new List<DeleteObjectRequest>();
        var page = new ListObjectsV2Response { IsTruncated = false };
        page.S3Objects.Add(new S3Object { Key = referenced, LastModified = DateTime.UtcNow.AddDays(-3) });
        page.S3Objects.Add(new S3Object { Key = orphan, LastModified = DateTime.UtcNow.AddDays(-3) });
        page.S3Objects.Add(new S3Object { Key = recent, LastModified = DateTime.UtcNow });
        page.S3Objects.Add(new S3Object { Key = unrelated, LastModified = DateTime.UtcNow.AddDays(-3) });

        client.Setup(x => x.ListObjectsV2Async(It.IsAny<ListObjectsV2Request>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(page);
        client.Setup(x => x.DeleteObjectAsync(It.IsAny<DeleteObjectRequest>(), It.IsAny<CancellationToken>()))
            .Callback<DeleteObjectRequest, CancellationToken>((request, _) => deleted.Add(request))
            .ReturnsAsync(new DeleteObjectResponse());

        var store = CreateStore(client.Object, "AES256");
        var removed = await store.ReconcilePublishedReportsAsync(
            DateTimeOffset.UtcNow.AddDays(-1),
            key => Task.FromResult(string.Equals(key, referenced, StringComparison.OrdinalIgnoreCase)),
            CancellationToken.None);

        Assert.Equal(1, removed);
        Assert.Single(deleted);
        Assert.Equal(orphan, deleted[0].Key);
        client.VerifyAll();
    }

    [Fact]
    public async Task Readiness_returns_false_for_storage_errors_and_propagates_cancellation()
    {
        var client = new Mock<IAmazonS3>(MockBehavior.Strict);
        client.Setup(x => x.ListObjectsV2Async(It.IsAny<ListObjectsV2Request>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new AmazonS3Exception("Bucket access denied"));
        var store = CreateStore(client.Object, "AES256");

        Assert.False(await store.CheckAvailabilityAsync(CancellationToken.None));
        client.VerifyAll();
    }

    private static S3AssessmentArtifactStore CreateStore(IAmazonS3 client, string encryption, string? kmsKeyId = null)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Artifacts:S3:Bucket"] = "sentinelai-artifacts",
            ["Artifacts:S3:ServerSideEncryption"] = encryption,
            ["Artifacts:S3:KmsKeyId"] = kmsKeyId
        }).Build();

        return new S3AssessmentArtifactStore(client, configuration);
    }
}
