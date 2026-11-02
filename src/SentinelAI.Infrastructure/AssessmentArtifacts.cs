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
        if (!storageKey.StartsWith($"{tenantId:D}/", StringComparison.OrdinalIgnoreCase)) return null;
        var path = Resolve(storageKey);
        return File.Exists(path) ? await File.ReadAllBytesAsync(path, cancellationToken) : null;
    }

    private string Resolve(string key)
    {
        var path = Path.GetFullPath(Path.Combine(root, key.Replace('/', Path.DirectorySeparatorChar)));
        if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Invalid assessment artifact path.");
        return path;
    }
}
