using Microsoft.Extensions.Configuration;
using SentinelAI.Agent.Vulnerability;

namespace SentinelAI.Infrastructure;

public sealed class FileSystemAssessmentArtifactStore(IConfiguration configuration) : IAssessmentArtifactStore
{
    private readonly string root = Path.GetFullPath(configuration["Artifacts:Root"] ?? Path.Combine(AppContext.BaseDirectory, "artifacts"));

    public async Task<string> PutAsync(Guid tenantId, Guid assessmentId, string name, byte[] content, CancellationToken cancellationToken)
    {
        var safeName = name.Replace('\\', '/').TrimStart('/');
        var key = $"{tenantId:D}/{assessmentId:D}/{safeName}";
        var path = Resolve(key);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllBytesAsync(path, content, cancellationToken);
        return key;
    }

    public async Task<byte[]?> GetAsync(Guid tenantId, string storageKey, CancellationToken cancellationToken)
    {
        if (!storageKey.StartsWith($"{tenantId:D}/", StringComparison.OrdinalIgnoreCase) || storageKey.Contains("/.staging/", StringComparison.OrdinalIgnoreCase)) return null;
        var path = Resolve(storageKey);
        return File.Exists(path) ? await File.ReadAllBytesAsync(path, cancellationToken) : null;
    }

    public async Task<string> StageReportAsync(Guid tenantId, Guid assessmentId, byte[] content, CancellationToken cancellationToken)
    {
        var key = $"{tenantId:D}/{assessmentId:D}/.staging/{Guid.NewGuid():N}.html";
        var path = ResolveOwnedReportPath(tenantId, assessmentId, key, requireStaging: true);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllBytesAsync(path, content, cancellationToken);
        return key;
    }

    public Task<string> PublishReportAsync(Guid tenantId, Guid assessmentId, string stagingKey, CancellationToken cancellationToken)
    {
        var source = ResolveOwnedReportPath(tenantId, assessmentId, stagingKey, requireStaging: true);
        if (!File.Exists(source)) throw new FileNotFoundException("The staged assessment report was not found.");
        var publishedKey = $"{tenantId:D}/{assessmentId:D}/reports/{Guid.NewGuid():N}.html";
        var destination = ResolveOwnedReportPath(tenantId, assessmentId, publishedKey, requireStaging: false);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.Move(source, destination);
        return Task.FromResult(publishedKey);
    }

    public async Task<byte[]?> GetPublishedReportAsync(Guid tenantId, Guid assessmentId, string storageKey, CancellationToken cancellationToken)
    {
        if (!storageKey.StartsWith($"{tenantId:D}/{assessmentId:D}/", StringComparison.OrdinalIgnoreCase)) return null;
        var path = ResolveOwnedReportPath(tenantId, assessmentId, storageKey, requireStaging: false);
        if (!storageKey.Contains("/reports/", StringComparison.OrdinalIgnoreCase) || !File.Exists(path)) return null;
        return await File.ReadAllBytesAsync(path, cancellationToken);
    }

    public Task DiscardReportAsync(Guid tenantId, Guid assessmentId, string storageKey, CancellationToken cancellationToken)
    {
        var path = ResolveOwnedReportPath(tenantId, assessmentId, storageKey, requireStaging: false);
        if (File.Exists(path)) File.Delete(path);
        return Task.CompletedTask;
    }

    public Task<int> CleanupStagedReportsAsync(DateTimeOffset olderThan, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(root)) return Task.FromResult(0);
        var removed = 0;
        foreach (var path in Directory.EnumerateFiles(root, "*.html", SearchOption.AllDirectories).Take(10_000))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!path.Contains($"{Path.DirectorySeparatorChar}.staging{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase)) continue;
            if (File.GetLastWriteTimeUtc(path) >= olderThan.UtcDateTime) continue;
            File.Delete(path);
            removed++;
        }
        return Task.FromResult(removed);
    }

    public async Task<int> ReconcilePublishedReportsAsync(DateTimeOffset olderThan, Func<string, Task<bool>> isReferencedAsync, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(root)) return 0;
        var removed = 0;
        var files = Directory.EnumerateFiles(root, "*.html", SearchOption.AllDirectories).Take(10_000).ToList();
        foreach (var path in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relative = Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/');
            var segments = relative.Split('/');
            if (segments.Length != 4 || !string.Equals(segments[2], "reports", StringComparison.OrdinalIgnoreCase)) continue;
            if (!Guid.TryParse(segments[0], out _) || !Guid.TryParse(segments[1], out _)) continue;
            if (relative.Contains(".staging", StringComparison.OrdinalIgnoreCase)) continue;

            try
            {
                var lastWrite = File.GetLastWriteTimeUtc(path);
                if (lastWrite >= olderThan.UtcDateTime) continue;

                var isReferenced = await isReferencedAsync(relative);
                if (!isReferenced)
                {
                    if (File.Exists(path))
                    {
                        File.Delete(path);
                        removed++;
                    }
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        return removed;
    }

    private string Resolve(string key)
    {
        var path = Path.GetFullPath(Path.Combine(root, key.Replace('/', Path.DirectorySeparatorChar)));
        if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Invalid assessment artifact path.");
        return path;
    }

    private string ResolveOwnedReportPath(Guid tenantId, Guid assessmentId, string storageKey, bool requireStaging)
    {
        var prefix = $"{tenantId:D}/{assessmentId:D}/";
        if (!storageKey.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Assessment artifact ownership mismatch.");
        var normalized = storageKey.Replace('\\', '/');
        var isStaging = normalized.Contains("/.staging/", StringComparison.OrdinalIgnoreCase);
        var isPublished = normalized.Contains("/reports/", StringComparison.OrdinalIgnoreCase);
        if ((!isStaging && !isPublished) || (requireStaging && !isStaging) || normalized.Contains("..", StringComparison.Ordinal))
            throw new InvalidOperationException("Invalid assessment report artifact key.");
        return Resolve(normalized);
    }
}
