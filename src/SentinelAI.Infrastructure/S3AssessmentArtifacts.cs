using Amazon.S3;
using Amazon.S3.Model;
using System.Net;

namespace SentinelAI.Infrastructure;

public interface IAssessmentArtifactStoreReadiness
{
    Task<bool> CheckAvailabilityAsync(CancellationToken cancellationToken);
}

public sealed class S3AssessmentArtifactStore(
    IAmazonS3 client,
    IConfiguration configuration) : SentinelAI.Agent.Vulnerability.IAssessmentArtifactStore, IAssessmentArtifactStoreReadiness
{
    private readonly string bucket = configuration["Artifacts:S3:Bucket"]
        ?? throw new InvalidOperationException("Artifacts:S3:Bucket is required.");
    private readonly string encryption = configuration["Artifacts:S3:ServerSideEncryption"] ?? "AES256";
    private readonly string? kmsKeyId = configuration["Artifacts:S3:KmsKeyId"];

    public async Task<string> PutAsync(Guid tenantId, Guid assessmentId, string name, byte[] content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        var key = $"{tenantId:D}/{assessmentId:D}/{NormalizeName(name)}";
        await PutContentAsync(key, content, cancellationToken);
        return key;
    }

    public async Task<byte[]?> GetAsync(Guid tenantId, string storageKey, CancellationToken cancellationToken)
    {
        if (!IsTenantKey(tenantId, storageKey) || storageKey.Contains("/.staging/", StringComparison.OrdinalIgnoreCase))
            return null;
        return await ReadObjectAsync(storageKey, cancellationToken);
    }

    public async Task<string> StageReportAsync(Guid tenantId, Guid assessmentId, byte[] content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        var key = $"{tenantId:D}/{assessmentId:D}/.staging/{Guid.NewGuid():N}.html";
        await PutContentAsync(key, content, cancellationToken, "text/html; charset=utf-8");
        return key;
    }

    public async Task<string> PublishReportAsync(Guid tenantId, Guid assessmentId, string stagingKey, CancellationToken cancellationToken)
    {
        ValidateOwnedReportKey(tenantId, assessmentId, stagingKey, requireStaging: true);
        var fileName = Path.GetFileName(stagingKey);
        var publishedKey = $"{tenantId:D}/{assessmentId:D}/reports/{fileName}";
        var copyRequest = new CopyObjectRequest
        {
            SourceBucket = bucket,
            SourceKey = stagingKey,
            DestinationBucket = bucket,
            DestinationKey = publishedKey,
            ServerSideEncryptionMethod = EncryptionMethod,
            ServerSideEncryptionKeyManagementServiceKeyId = EncryptionKeyId
        };
        await client.CopyObjectAsync(copyRequest, cancellationToken);
        await client.DeleteObjectAsync(new DeleteObjectRequest { BucketName = bucket, Key = stagingKey }, cancellationToken);
        return publishedKey;
    }

    public async Task<byte[]?> GetPublishedReportAsync(Guid tenantId, Guid assessmentId, string storageKey, CancellationToken cancellationToken)
    {
        try { ValidateOwnedReportKey(tenantId, assessmentId, storageKey, requireStaging: false); }
        catch (InvalidOperationException) { return null; }
        return await ReadObjectAsync(storageKey, cancellationToken);
    }

    public async Task DiscardReportAsync(Guid tenantId, Guid assessmentId, string storageKey, CancellationToken cancellationToken)
    {
        ValidateOwnedReportKey(tenantId, assessmentId, storageKey, requireStaging: false);
        await client.DeleteObjectAsync(new DeleteObjectRequest { BucketName = bucket, Key = storageKey }, cancellationToken);
    }

    public async Task<int> CleanupStagedReportsAsync(DateTimeOffset olderThan, CancellationToken cancellationToken)
    {
        var removed = 0;
        await foreach (var item in ListObjectsAsync(cancellationToken))
        {
            if (!item.Key.Contains("/.staging/", StringComparison.OrdinalIgnoreCase) ||
                new DateTimeOffset(item.LastModified.ToUniversalTime()) >= olderThan)
                continue;

            await client.DeleteObjectAsync(new DeleteObjectRequest { BucketName = bucket, Key = item.Key }, cancellationToken);
            removed++;
        }
        return removed;
    }

    public async Task<int> ReconcilePublishedReportsAsync(
        DateTimeOffset olderThan,
        Func<string, Task<bool>> isReferencedAsync,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(isReferencedAsync);
        var removed = 0;
        await foreach (var item in ListObjectsAsync(cancellationToken))
        {
            var segments = item.Key.Split('/');
            if (segments.Length != 4 || !Guid.TryParse(segments[0], out _) ||
                !Guid.TryParse(segments[1], out _) ||
                !string.Equals(segments[2], "reports", StringComparison.OrdinalIgnoreCase))
                continue;
            if (new DateTimeOffset(item.LastModified.ToUniversalTime()) >= olderThan)
                continue;

            if (!await isReferencedAsync(item.Key))
            {
                await client.DeleteObjectAsync(new DeleteObjectRequest { BucketName = bucket, Key = item.Key }, cancellationToken);
                removed++;
            }
        }
        return removed;
    }

    public async Task<bool> CheckAvailabilityAsync(CancellationToken cancellationToken)
    {
        try
        {
            await client.ListObjectsV2Async(new ListObjectsV2Request { BucketName = bucket, MaxKeys = 1 }, cancellationToken);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return false; }
    }

    private async Task PutContentAsync(string key, byte[] content, CancellationToken cancellationToken, string? contentType = null)
    {
        await using var stream = new MemoryStream(content, writable: false);
        var request = new PutObjectRequest
        {
            BucketName = bucket,
            Key = key,
            InputStream = stream,
            ContentType = contentType ?? ContentTypeFor(key),
            ServerSideEncryptionMethod = EncryptionMethod,
            ServerSideEncryptionKeyManagementServiceKeyId = EncryptionKeyId
        };
        await client.PutObjectAsync(request, cancellationToken);
    }

    private async Task<byte[]?> ReadObjectAsync(string key, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await client.GetObjectAsync(new GetObjectRequest { BucketName = bucket, Key = key }, cancellationToken);
            await using var buffer = new MemoryStream();
            await response.ResponseStream.CopyToAsync(buffer, cancellationToken);
            return buffer.ToArray();
        }
        catch (AmazonS3Exception exception) when (exception.StatusCode == HttpStatusCode.NotFound ||
                                                   exception.ErrorCode is "NoSuchKey" or "NotFound")
        {
            return null;
        }
    }

    private async IAsyncEnumerable<S3Object> ListObjectsAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        string? continuationToken = null;
        var visited = 0;
        do
        {
            var page = await client.ListObjectsV2Async(new ListObjectsV2Request
            {
                BucketName = bucket,
                ContinuationToken = continuationToken,
                MaxKeys = 1000
            }, cancellationToken);

            foreach (var item in page.S3Objects)
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return item;
                if (++visited >= 10_000) yield break;
            }

            continuationToken = page.IsTruncated ? page.NextContinuationToken : null;
        }
        while (!string.IsNullOrWhiteSpace(continuationToken));
    }

    private ServerSideEncryptionMethod EncryptionMethod
        => string.Equals(encryption, "aws:kms", StringComparison.OrdinalIgnoreCase)
            ? ServerSideEncryptionMethod.AWSKMS
            : ServerSideEncryptionMethod.AES256;

    private string? EncryptionKeyId
        => string.Equals(encryption, "aws:kms", StringComparison.OrdinalIgnoreCase) ? kmsKeyId : null;

    private static bool IsTenantKey(Guid tenantId, string? storageKey)
    {
        if (string.IsNullOrWhiteSpace(storageKey) ||
            !storageKey.StartsWith($"{tenantId:D}/", StringComparison.OrdinalIgnoreCase))
            return false;
        return !storageKey.Split('/').Any(segment => segment is "." or "..");
    }

    private static void ValidateOwnedReportKey(Guid tenantId, Guid assessmentId, string storageKey, bool requireStaging)
    {
        var prefix = $"{tenantId:D}/{assessmentId:D}/";
        if (!storageKey.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
            storageKey.Split('/').Any(segment => segment is "." or ".."))
            throw new InvalidOperationException("Assessment artifact ownership mismatch.");

        var normalized = storageKey.Replace('\\', '/');
        var isStaging = normalized.Contains("/.staging/", StringComparison.OrdinalIgnoreCase);
        var isPublished = normalized.Contains("/reports/", StringComparison.OrdinalIgnoreCase);
        if ((!isStaging && !isPublished) || (requireStaging && !isStaging) ||
            (!requireStaging && !isPublished))
            throw new InvalidOperationException("Invalid assessment report artifact key.");
    }

    private static string NormalizeName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("An artifact name is required.", nameof(name));
        var normalized = name.Replace('\\', '/').Trim('/');
        var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0 || segments.Any(segment => segment is "." or ".." or ".staging" or "reports"))
            throw new ArgumentException("The artifact name contains an unsafe or reserved path segment.", nameof(name));
        return string.Join('/', segments);
    }

    private static string ContentTypeFor(string key)
        => Path.GetExtension(key).ToLowerInvariant() switch
        {
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".json" => "application/json",
            ".html" => "text/html; charset=utf-8",
            ".txt" => "text/plain; charset=utf-8",
            _ => "application/octet-stream"
        };
}
