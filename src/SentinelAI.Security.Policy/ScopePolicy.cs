using System.Net;
using System.Net.Sockets;
using SentinelAI.Domain;

namespace SentinelAI.Security.Policy;

public sealed record ScopeValidationResult(bool IsValid, IReadOnlyList<string> Errors)
{
    public static ScopeValidationResult Valid() => new(true, []);
    public static ScopeValidationResult Invalid(params string[] errors) => new(false, errors);
}

public interface ITargetScopeValidator
{
    ScopeValidationResult ValidateDefinition(TargetScope scope, Guid tenantId, DateTimeOffset now);
    ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, string target, string operationProfile, CancellationToken cancellationToken = default);
}

public interface IHostAddressResolver
{
    Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken);
}

public sealed class SystemHostAddressResolver : IHostAddressResolver
{
    public async Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
        => await Dns.GetHostAddressesAsync(host, cancellationToken);
}

public sealed class TargetScopeValidator(IHostAddressResolver resolver) : ITargetScopeValidator
{
    private static readonly string[] PublicAddressPrefixes = ["0.", "127.", "169.254.", "224.", "255."];

    public ScopeValidationResult ValidateDefinition(TargetScope scope, Guid tenantId, DateTimeOffset now)
    {
        var errors = new List<string>();
        if (scope.TenantId != tenantId) errors.Add("Scope belongs to a different tenant.");
        if (scope.ExpiresAt <= now) errors.Add("Scope authorization is expired.");
        if (scope.Targets.Count == 0) errors.Add("At least one authorized target is required.");
        if (string.IsNullOrWhiteSpace(scope.AuthorizationEvidence)) errors.Add("Authorization evidence is required.");
        if (scope.ApprovedOperationProfiles.Count == 0) errors.Add("At least one operation profile is required.");
        if (scope.RequestsPerMinute is < 1 or > 10_000) errors.Add("Requests per minute must be between 1 and 10000.");
        if (scope.MaxExecutionSeconds is < 1 or > 86_400) errors.Add("Maximum execution time is invalid.");

        foreach (var target in scope.Targets)
        {
            if (!IsValidTarget(target, out var error)) errors.Add(error!);
            if (IsPublicTarget(target) && !scope.PublicTargetOwnershipVerified)
                errors.Add($"Public target '{target.Value}' requires ownership verification.");
        }

        foreach (var exclusion in scope.Exclusions)
        {
            if (string.IsNullOrWhiteSpace(exclusion)) errors.Add("Exclusions cannot be empty.");
        }

        return errors.Count == 0 ? ScopeValidationResult.Valid() : new ScopeValidationResult(false, errors);
    }

    public async ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, string target, string operationProfile, CancellationToken cancellationToken = default)
    {
        var definition = ValidateDefinition(scope, tenantId, DateTimeOffset.UtcNow);
        if (!definition.IsValid) return definition;
        if (!scope.ApprovedOperationProfiles.Contains(operationProfile, StringComparer.OrdinalIgnoreCase))
            return ScopeValidationResult.Invalid("Operation profile is not approved by the scope.");

        var normalizedTarget = target.Trim().TrimEnd('.').ToLowerInvariant();
        if (scope.Exclusions.Any(exclusion => normalizedTarget.Equals(exclusion.Trim().TrimEnd('.').ToLowerInvariant(), StringComparison.OrdinalIgnoreCase)))
            return ScopeValidationResult.Invalid("Target is explicitly excluded.");

        var matching = scope.Targets.Where(t => t.Kind == TargetKind.Network).ToList();
        foreach (var definitionTarget in matching)
        {
            if (IPAddress.TryParse(normalizedTarget, out var address) && IsWithinNetwork(address, definitionTarget.Value))
                return ScopeValidationResult.Valid();

            if (definitionTarget.Value.Equals(normalizedTarget, StringComparison.OrdinalIgnoreCase))
                return ScopeValidationResult.Valid();

            if (definitionTarget.Kind == TargetKind.Network && !IPAddress.TryParse(definitionTarget.Value, out _) && !IPAddress.TryParse(normalizedTarget, out _))
            {
                IReadOnlyCollection<IPAddress> addresses;
                try { addresses = await resolver.ResolveAsync(normalizedTarget, cancellationToken); }
                catch (SocketException) { return ScopeValidationResult.Invalid("Target could not be resolved safely."); }
                if (addresses.Count > 0 && addresses.All(address => IsWithinNetwork(address, definitionTarget.Value)))
                    return ScopeValidationResult.Valid();
            }
        }

        return ScopeValidationResult.Invalid("Target is outside the authorized scope.");
    }

    private static bool IsValidTarget(TargetDefinition target, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(target.Value)) { error = "Target values cannot be empty."; return false; }
        if (target.Kind == TargetKind.Network)
        {
            var parts = target.Value.Split('/', StringSplitOptions.TrimEntries);
            if (!IPAddress.TryParse(parts[0], out var address))
            {
                if (!IsHostname(parts[0])) { error = $"Network target '{target.Value}' is not a valid IP, CIDR or hostname."; return false; }
                return true;
            }
            if (parts.Length == 2 && (!int.TryParse(parts[1], out var prefix) || prefix < 0 || prefix > address.GetAddressBytes().Length * 8))
            { error = $"Network target '{target.Value}' has an invalid CIDR prefix."; return false; }
            if (parts.Length > 2) { error = $"Network target '{target.Value}' has an invalid format."; return false; }
            return true;
        }
        if (target.Kind == TargetKind.Web)
        {
            if (!Uri.TryCreate(target.Value, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") || string.IsNullOrEmpty(uri.Host))
            { error = $"Web target '{target.Value}' must be an absolute HTTP(S) URL."; return false; }
            return true;
        }
        if (!Uri.TryCreate(target.Value, UriKind.Absolute, out var repo) || repo.Host is not "github.com" and not "www.github.com" || repo.Segments.Length < 3)
        { error = $"Code target '{target.Value}' must be an authorized GitHub repository URL."; return false; }
        return true;
    }

    private static bool IsHostname(string value) => value.Length <= 253 && value.All(c => char.IsLetterOrDigit(c) || c is '.' or '-' or ':');

    private static bool IsPublicTarget(TargetDefinition target)
    {
        if (target.Kind != TargetKind.Network) return true;
        var host = target.Value.Split('/')[0];
        if (!IPAddress.TryParse(host, out var address)) return true;
        var bytes = address.GetAddressBytes();
        return !IPAddress.IsLoopback(address) && !address.IsIPv6LinkLocal && !address.IsIPv6SiteLocal &&
            !(bytes.Length == 4 && (bytes[0] == 10 || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) || (bytes[0] == 192 && bytes[1] == 168))) &&
            !PublicAddressPrefixes.Any(prefix => host.StartsWith(prefix, StringComparison.Ordinal));
    }

    private static bool IsWithinNetwork(IPAddress address, string definition)
    {
        var parts = definition.Split('/', StringSplitOptions.TrimEntries);
        if (!IPAddress.TryParse(parts[0], out var network)) return false;
        if (network.AddressFamily != address.AddressFamily) return false;
        var prefix = parts.Length == 2 && int.TryParse(parts[1], out var parsed) ? parsed : network.GetAddressBytes().Length * 8;
        var networkBytes = network.GetAddressBytes(); var addressBytes = address.GetAddressBytes();
        var fullBytes = prefix / 8; var remainingBits = prefix % 8;
        for (var i = 0; i < fullBytes; i++) if (networkBytes[i] != addressBytes[i]) return false;
        return remainingBits == 0 || (networkBytes[fullBytes] & (byte)(0xFF << (8 - remainingBits))) == (addressBytes[fullBytes] & (byte)(0xFF << (8 - remainingBits)));
    }
}
