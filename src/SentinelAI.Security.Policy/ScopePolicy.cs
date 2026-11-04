using System.Net;
using System.Net.Sockets;
using System.Numerics;
using SentinelAI.Domain;

namespace SentinelAI.Security.Policy;

public sealed record ValidatedExecutionTarget(string OriginalHostname, IReadOnlyCollection<IPAddress> ApprovedAddresses,
    DateTimeOffset ResolvedAt, Guid ScopeId, Guid TenantId, DateTimeOffset ExpiresAt, string OperationProfile);
public sealed record WorkerExecutionContext(string Identity, IReadOnlyCollection<string> Capabilities, IReadOnlyCollection<string>? ApprovedPrivateNetworkRanges = null);

public sealed record ScopeValidationResult(bool IsValid, IReadOnlyList<string> Errors, ValidatedExecutionTarget? ValidatedTarget = null)
{
    public static ScopeValidationResult Valid(ValidatedExecutionTarget? target = null) => new(true, [], target);
    public static ScopeValidationResult Invalid(params string[] errors) => new(false, errors);
}

public interface ITargetScopeValidator
{
    ScopeValidationResult ValidateDefinition(TargetScope scope, Guid tenantId, DateTimeOffset now);
    ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, string target, string operationProfile, CancellationToken cancellationToken = default);
    ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, TargetKind kind, string target, string operationProfile, CancellationToken cancellationToken = default);
    ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, TargetKind kind, string target, string operationProfile, WorkerExecutionContext? worker, CancellationToken cancellationToken = default);
    ValueTask<ScopeValidationResult> ValidateRedirectAsync(TargetScope scope, Guid tenantId, Uri redirect, string operationProfile, CancellationToken cancellationToken = default);
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
        if (scope.WebHostingMode is not null && scope.MaxExecutionSeconds > 600)
            errors.Add("Web assessment execution time cannot exceed 600 seconds.");
        if (scope.MaxTotalRequests is < 1 or > 100_000) errors.Add("Maximum total requests is invalid.");
        if (scope.MaxConcurrentRequests is < 1 or > 64) errors.Add("Maximum concurrent requests is invalid.");
        if (scope.MaxPages is < 1 or > 10_000) errors.Add("Maximum page count is invalid.");
        if (scope.MaxCrawlDepth is < 0 or > 20) errors.Add("Maximum crawl depth is invalid.");
        if (scope.MaxResponseBytes is < 1_024 or > 10 * 1024 * 1024) errors.Add("Maximum response size is invalid.");

        foreach (var target in scope.Targets)
        {
            if (!TryValidateTarget(target, out var error, out var requiresPublicAuthorization))
            {
                errors.Add(error!);
                continue;
            }
            var privateWebTarget = target.Kind == TargetKind.Web && scope.WebHostingMode == WebHostingMode.Private && !string.IsNullOrWhiteSpace(scope.PrivateWorkerIdentity);
            if (requiresPublicAuthorization && !privateWebTarget && !HasValidPublicAuthorization(scope, target, now))
                errors.Add($"Public target '{target.Value}' requires a current ownership authorization verification record.");
        }
        foreach (var exclusion in scope.Exclusions)
            if (!TryValidateExclusion(exclusion, out var error)) errors.Add(error!);
        return errors.Count == 0 ? ScopeValidationResult.Valid() : new ScopeValidationResult(false, errors);
    }

    public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, string target, string operationProfile, CancellationToken cancellationToken = default)
        => ValidateExecutionAsync(scope, tenantId, TargetKind.Network, target, operationProfile, cancellationToken);

    public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, TargetKind kind, string target, string operationProfile, CancellationToken cancellationToken = default)
        => ValidateExecutionAsync(scope, tenantId, kind, target, operationProfile, null, cancellationToken);

    public async ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, TargetKind kind, string target, string operationProfile, WorkerExecutionContext? worker, CancellationToken cancellationToken = default)
    {
        var definition = ValidateDefinition(scope, tenantId, DateTimeOffset.UtcNow);
        if (!definition.IsValid) return definition;
        if (!scope.ApprovedOperationProfiles.Contains(operationProfile.Trim(), StringComparer.OrdinalIgnoreCase))
            return ScopeValidationResult.Invalid("Operation profile is not approved by the scope.");
        if (string.IsNullOrWhiteSpace(target)) return ScopeValidationResult.Invalid("Execution target is empty.");
        if (IsExcluded(scope.Exclusions, target)) return ScopeValidationResult.Invalid("Target is explicitly excluded.");
        return kind switch
        {
            TargetKind.Network => await ValidateNetworkExecutionAsync(scope, target, operationProfile, cancellationToken),
            TargetKind.Web => await ValidateWebExecutionAsync(scope, target, operationProfile, worker, cancellationToken),
            TargetKind.Code => ValidateCodeExecution(scope, target, operationProfile),
            _ => ScopeValidationResult.Invalid("Target kind is not supported.")
        };
    }

    public ValueTask<ScopeValidationResult> ValidateRedirectAsync(TargetScope scope, Guid tenantId, Uri redirect, string operationProfile, CancellationToken cancellationToken = default)
    {
        if (redirect is null || redirect.Scheme is not ("http" or "https") || string.IsNullOrWhiteSpace(redirect.Host))
            return ValueTask.FromResult(ScopeValidationResult.Invalid("Redirect is not a valid HTTP(S) URL."));
        return ValidateExecutionAsync(scope, tenantId, TargetKind.Web, redirect.ToString(), operationProfile, cancellationToken);
    }

    private async ValueTask<ScopeValidationResult> ValidateNetworkExecutionAsync(TargetScope scope, string target, string operationProfile, CancellationToken cancellationToken)
    {
        if (TryParseCidr(target.Trim(), out var networkAddress, out var targetPrefix))
        {
            if (CidrIntersectsDisallowed(target)) return ScopeValidationResult.Invalid("Target range intersects a reserved or special-purpose address range.");
            if (IsExcluded(scope.Exclusions, target)) return ScopeValidationResult.Invalid("Target is explicitly excluded.");
            return scope.Targets.Where(x => x.Kind == TargetKind.Network).Any(x => CidrContains(x.Value, target))
                ? ScopeValidationResult.Valid(new ValidatedExecutionTarget(target, [networkAddress], DateTimeOffset.UtcNow, scope.Id, scope.TenantId, scope.ExpiresAt, operationProfile)) : ScopeValidationResult.Invalid("Target is outside the authorized scope.");
        }
        if (IPAddress.TryParse(target.Trim(), out var address))
        {
            if (IsDisallowedAddress(address)) return ScopeValidationResult.Invalid("Target resolves to a reserved or special-purpose address.");
            if (IsExcluded(scope.Exclusions, target, [address])) return ScopeValidationResult.Invalid("Target is explicitly excluded.");
            return scope.Targets.Any(x => x.Kind == TargetKind.Network && IsWithinNetwork(address, x.Value))
                ? ScopeValidationResult.Valid(new ValidatedExecutionTarget(target, [NormalizeAddress(address)], DateTimeOffset.UtcNow, scope.Id, scope.TenantId, scope.ExpiresAt, operationProfile)) : ScopeValidationResult.Invalid("Target is outside the authorized scope.");
        }
        var hostname = target.Trim().TrimEnd('.');
        if (!IsValidHostname(hostname)) return ScopeValidationResult.Invalid("Target is not a valid hostname or IP address.");
        IReadOnlyCollection<IPAddress> resolved;
        try { resolved = await resolver.ResolveAsync(hostname, cancellationToken); }
        catch (SocketException) { return ScopeValidationResult.Invalid("Target could not be resolved safely."); }
        if (resolved.Count == 0 || resolved.Any(IsDisallowedAddress)) return ScopeValidationResult.Invalid("DNS resolution returned a reserved address or no usable address.");
        if (IsExcluded(scope.Exclusions, hostname, resolved)) return ScopeValidationResult.Invalid("A resolved target address is explicitly excluded.");
        foreach (var authorized in scope.Targets.Where(x => x.Kind == TargetKind.Network))
        {
            if (IPAddress.TryParse(authorized.Value.Split('/')[0], out _))
            {
                if (resolved.All(ip => IsWithinNetwork(ip, authorized.Value))) return ScopeValidationResult.Valid(CreateValidatedTarget(hostname, resolved, scope, operationProfile));
            }
            else if (DomainMatches(hostname, authorized.Value, false) && resolved.All(ip => !IsPrivateAddress(ip))) return ScopeValidationResult.Valid(CreateValidatedTarget(hostname, resolved, scope, operationProfile));
        }
        return ScopeValidationResult.Invalid("Target is outside the authorized scope.");
    }

    private async ValueTask<ScopeValidationResult> ValidateWebExecutionAsync(TargetScope scope, string target, string operationProfile, WorkerExecutionContext? worker, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || !IsValidWebHost(uri.Host) || uri.UserInfo.Length > 0)
            return ScopeValidationResult.Invalid("Web target must be an absolute HTTP(S) URL without credentials.");
        if (!IsSafeWebPath(uri.AbsolutePath)) return ScopeValidationResult.Invalid("Web target path contains an ambiguous or unsafe encoding.");
        IReadOnlyCollection<IPAddress> resolved;
        try { resolved = await resolver.ResolveAsync(uri.Host, cancellationToken); }
        catch (SocketException) { return ScopeValidationResult.Invalid("Web target could not be resolved safely."); }
        if (resolved.Count == 0 || resolved.Any(IsDisallowedAddress)) return ScopeValidationResult.Invalid("Web target DNS resolution is unsafe.");
        if (scope.WebHostingMode == WebHostingMode.Private)
        {
            if (string.IsNullOrWhiteSpace(scope.PrivateWorkerIdentity) || worker is null || !scope.PrivateWorkerIdentity.Equals(worker.Identity.Trim(), StringComparison.Ordinal) || !worker.Capabilities.Contains("private-web-assessment", StringComparer.OrdinalIgnoreCase))
                return ScopeValidationResult.Invalid("Private web assessments require the explicitly assigned private worker capability.");
            if (resolved.Any(ip => !IsPrivateAddress(ip))) return ScopeValidationResult.Invalid("Private web targets must resolve only to private address space.");
            if (scope.ApprovedPrivateNetworkRanges.Count > 0)
            {
                if (worker.ApprovedPrivateNetworkRanges is null || worker.ApprovedPrivateNetworkRanges.Count == 0)
                    return ScopeValidationResult.Invalid("Private web targets require administrator-approved worker network ranges.");
                if (resolved.Any(ip => !scope.ApprovedPrivateNetworkRanges.Any(range => IsWithinNetwork(ip, range)) || !worker.ApprovedPrivateNetworkRanges.Any(range => IsWithinNetwork(ip, range))))
                    return ScopeValidationResult.Invalid("Private web target resolved outside the effective approved network scope.");
            }
        }
        else if (resolved.Any(IsPrivateAddress)) return ScopeValidationResult.Invalid("Public web target DNS resolution is unsafe.");
        if (IsExcluded(scope.Exclusions, uri.Host, resolved) || IsExcluded(scope.Exclusions, uri.ToString(), resolved)) return ScopeValidationResult.Invalid("Web target or a resolved redirect destination is explicitly excluded.");
        foreach (var authorized in scope.Targets.Where(x => x.Kind == TargetKind.Web))
        {
            if (!Uri.TryCreate(authorized.Value, UriKind.Absolute, out var baseUri)) continue;
            var hostMatches = uri.Host.Equals(baseUri.Host, StringComparison.OrdinalIgnoreCase) || (scope.AllowSubdomains && DomainMatches(uri.Host, baseUri.Host, true));
            if (baseUri.Scheme.Equals(uri.Scheme, StringComparison.OrdinalIgnoreCase) && EffectivePort(baseUri) == EffectivePort(uri) && hostMatches && IsPathWithin(baseUri.AbsolutePath, uri.AbsolutePath))
                return ScopeValidationResult.Valid(CreateValidatedTarget(uri.Host, resolved, scope, operationProfile));
        }
        return ScopeValidationResult.Invalid("Web target or redirect is outside the authorized scope.");
    }

    private static ScopeValidationResult ValidateCodeExecution(TargetScope scope, string target, string operationProfile)
    {
        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri) || !uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase))
            return ScopeValidationResult.Invalid("Code target must be an authorized GitHub repository URL.");
        return scope.Targets.Where(x => x.Kind == TargetKind.Code).Any(x => Uri.TryCreate(x.Value, UriKind.Absolute, out var allowed) && allowed.Host.Equals(uri.Host, StringComparison.OrdinalIgnoreCase) && string.Equals(NormalizeRepositoryPath(allowed.AbsolutePath), NormalizeRepositoryPath(uri.AbsolutePath), StringComparison.OrdinalIgnoreCase))
            ? ScopeValidationResult.Valid(new ValidatedExecutionTarget(uri.Host, [], DateTimeOffset.UtcNow, scope.Id, scope.TenantId, scope.ExpiresAt, operationProfile)) : ScopeValidationResult.Invalid("Code target is outside the authorized repository scope.");
    }

    private static bool TryValidateTarget(TargetDefinition target, out string? error, out bool requiresPublicAuthorization)
    {
        error = null; requiresPublicAuthorization = false;
        if (string.IsNullOrWhiteSpace(target.Value)) { error = "Target values cannot be empty."; return false; }
        var value = target.Value.Trim();
        switch (target.Kind)
        {
            case TargetKind.Network:
                if (TryParseCidr(value, out _, out _))
                {
                    if (CidrIntersectsDisallowed(value)) { error = $"Network target '{value}' intersects a reserved or special-purpose range."; return false; }
                    requiresPublicAuthorization = !IsCidrEntirelyPrivate(value); return true;
                }
                if (!IsValidHostname(value)) { error = $"Network target '{value}' is not a strict IP, CIDR or hostname."; return false; }
                requiresPublicAuthorization = true; return true;
            case TargetKind.Web:
                if (!Uri.TryCreate(value, UriKind.Absolute, out var web) || web.Scheme is not ("http" or "https") || !IsValidWebHost(web.Host) || web.UserInfo.Length > 0 || !IsSafeWebPath(web.AbsolutePath))
                { error = $"Web target '{value}' must be an absolute HTTP(S) URL without credentials."; return false; }
                requiresPublicAuthorization = true; return true;
            case TargetKind.Code:
                if (!Uri.TryCreate(value, UriKind.Absolute, out var repo) || !repo.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) || NormalizeRepositoryPath(repo.AbsolutePath).Split('/').Length != 2)
                { error = $"Code target '{value}' must be an authorized GitHub repository URL."; return false; }
                requiresPublicAuthorization = true; return true;
            default:
                error = "Target kind is not supported."; return false;
        }
    }

    private static bool TryValidateExclusion(string exclusion, out string? error)
    {
        error = null; var value = exclusion.Trim();
        if (value.Length == 0) { error = "Exclusions cannot be empty."; return false; }
        if (TryParseCidr(value, out var address, out _))
        {
            if (IsDisallowedAddress(address)) { error = $"Exclusion '{value}' is reserved or special-purpose."; return false; }
            return true;
        }
        if (Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https" && IsValidHostname(uri.Host)) return true;
        if (IsValidHostname(value.TrimEnd('.'))) return true;
        error = $"Exclusion '{value}' is not a valid IP, CIDR, hostname or URL."; return false;
    }

    private static bool IsExcluded(IEnumerable<string> exclusions, string target, IReadOnlyCollection<IPAddress>? resolved = null)
    {
        var value = target.Trim().TrimEnd('.');
        var address = IPAddress.TryParse(value, out var parsed) ? parsed : null;
        Uri.TryCreate(value, UriKind.Absolute, out var uri);
        foreach (var exclusion in exclusions)
        {
            var candidate = exclusion.Trim().TrimEnd('.');
            if (TryParseCidr(candidate, out _, out _))
            {
                if (address is not null && IsWithinNetwork(address, candidate)) return true;
                if (TryParseCidr(value, out _, out _) && CidrRangesIntersect(value, candidate)) return true;
                if (resolved is not null && resolved.Any(ip => IsWithinNetwork(ip, candidate))) return true;
            }
            if (uri is not null && Uri.TryCreate(candidate, UriKind.Absolute, out var exclusionUri) && uri.Scheme.Equals(exclusionUri.Scheme, StringComparison.OrdinalIgnoreCase) && exclusionUri.Port == uri.Port && DomainMatches(uri.Host, exclusionUri.Host, true) && IsPathWithin(exclusionUri.AbsolutePath, uri.AbsolutePath)) return true;
            if (DomainMatches(uri?.Host ?? value, candidate, true) || string.Equals(value, candidate, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static bool HasValidPublicAuthorization(TargetScope scope, TargetDefinition target, DateTimeOffset now)
        => scope.PublicTargetVerifications.Any(x => x.VerifiedAt <= now && (x.ExpiresAt is null || x.ExpiresAt > now) && !string.IsNullOrWhiteSpace(x.Evidence) && !string.IsNullOrWhiteSpace(x.Verifier) && !string.IsNullOrWhiteSpace(x.Method) && VerificationMatches(x.Target, target.Value));

    private static bool VerificationMatches(string verified, string target)
    {
        if (TryParseCidr(verified.Trim(), out var verifiedAddress, out var verifiedPrefix) && TryParseCidr(target.Trim(), out var targetAddress, out var targetPrefix))
            return verifiedAddress.AddressFamily == targetAddress.AddressFamily && CidrContains($"{verifiedAddress}/{verifiedPrefix}", $"{targetAddress}/{targetPrefix}");
        if (Uri.TryCreate(verified, UriKind.Absolute, out var verifiedUri) && Uri.TryCreate(target, UriKind.Absolute, out var targetUri))
            return verifiedUri.Scheme.Equals(targetUri.Scheme, StringComparison.OrdinalIgnoreCase) && EffectivePort(verifiedUri) == EffectivePort(targetUri) && verifiedUri.Host.Equals(targetUri.Host, StringComparison.OrdinalIgnoreCase) && IsPathWithin(verifiedUri.AbsolutePath, targetUri.AbsolutePath);
        return string.Equals(verified.Trim().TrimEnd('.'), target.Trim().TrimEnd('.'), StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryParseCidr(string value, out IPAddress address, out int prefix)
    {
        address = IPAddress.None; prefix = -1;
        var parts = value.Split('/', StringSplitOptions.None);
        if (parts.Length > 2 || parts.Any(string.IsNullOrWhiteSpace) || parts[0].Contains('%')) return false;
        if (!IPAddress.TryParse(parts[0], out var parsed) || parsed is null) return false;
        address = NormalizeAddress(parsed);
        var max = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (parts.Length == 1) { prefix = max; return true; }
        if (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > max) return false;
        return true;
    }

    private static bool TryGetCidrRange(string value, out IPAddress start, out IPAddress end, out int prefix)
    {
        start = IPAddress.None; end = IPAddress.None; prefix = -1;
        if (!TryParseCidr(value.Trim(), out var address, out prefix)) return false;
        var bytes = address.GetAddressBytes();
        var fullBytes = prefix / 8;
        var remainingBits = prefix % 8;
        if (remainingBits != 0)
        {
            bytes[fullBytes] &= (byte)(0xFF << (8 - remainingBits));
            for (var index = fullBytes + 1; index < bytes.Length; index++) bytes[index] = 0;
        }
        else for (var index = fullBytes; index < bytes.Length; index++) bytes[index] = 0;
        start = new IPAddress(bytes);
        var endBytes = start.GetAddressBytes();
        if (remainingBits != 0) endBytes[fullBytes] |= (byte)(0xFF >> remainingBits);
        for (var index = fullBytes + (remainingBits == 0 ? 0 : 1); index < endBytes.Length; index++) endBytes[index] = 0xFF;
        end = new IPAddress(endBytes);
        return true;
    }

    private static bool CidrRangesIntersect(string left, string right)
    {
        if (!TryGetCidrRange(left, out var leftStart, out var leftEnd, out _) || !TryGetCidrRange(right, out var rightStart, out var rightEnd, out _) || leftStart.AddressFamily != rightStart.AddressFamily) return false;
        return ToNumber(leftStart) <= ToNumber(rightEnd) && ToNumber(rightStart) <= ToNumber(leftEnd);
    }

    private static bool CidrContains(string authorized, string candidate)
    {
        if (!TryGetCidrRange(authorized, out var authorizedStart, out var authorizedEnd, out _) || !TryGetCidrRange(candidate, out var candidateStart, out var candidateEnd, out _) || authorizedStart.AddressFamily != candidateStart.AddressFamily) return false;
        return ToNumber(authorizedStart) <= ToNumber(candidateStart) && ToNumber(candidateEnd) <= ToNumber(authorizedEnd);
    }

    private static bool IsCidrEntirelyPrivate(string definition)
        => CidrContainedByAny(definition, ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]);

    private static bool CidrContainedByAny(string definition, IReadOnlyCollection<string> networks)
        => networks.Any(network => CidrContains(network, definition));

    private static bool CidrIntersectsDisallowed(string definition)
        => new[] { "0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "100::/64", "64:ff9b::/96", "2001::/32", "2001:2::/48", "2001:10::/28", "2001:20::/28", "2001:db8::/32", "2002::/16", "fe80::/10", "ff00::/8" }
            .Any(disallowed => CidrRangesIntersect(definition, disallowed));

    private static BigInteger ToNumber(IPAddress address) => new(address.GetAddressBytes(), isUnsigned: true, isBigEndian: true);

    private static bool IsValidHostname(string value)
    {
        value = value.Trim().TrimEnd('.');
        if (value.Length is 0 or > 253 || value.Contains('/') || value.Contains(':') || IPAddress.TryParse(value, out _)) return false;
        var labels = value.Split('.');
        return labels.Length >= 2 && labels.All(label => label.Length is > 0 and <= 63 && label[0] != '-' && label[^1] != '-' && label.All(c => char.IsLetterOrDigit(c) || c == '-'));
    }

    private static bool IsValidWebHost(string value)
        => IPAddress.TryParse(value, out var address) ? !IsDisallowedAddress(address) : IsValidHostname(value);

    private static bool DomainMatches(string candidate, string authorized, bool allowSubdomains)
    {
        var left = candidate.Trim().TrimEnd('.'); var right = authorized.Trim().TrimEnd('.');
        return left.Equals(right, StringComparison.OrdinalIgnoreCase) || (allowSubdomains && left.EndsWith('.' + right, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsPathWithin(string basePath, string candidatePath)
    {
        var normalizedBase = string.IsNullOrWhiteSpace(basePath) ? "/" : "/" + basePath.Trim('/');
        var baseValue = normalizedBase == "/" ? "/" : normalizedBase + "/";
        var candidate = string.IsNullOrWhiteSpace(candidatePath) ? "/" : candidatePath;
        return candidate.Equals(normalizedBase, StringComparison.OrdinalIgnoreCase) || candidate.StartsWith(baseValue, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSafeWebPath(string path)
    {
        if (string.IsNullOrEmpty(path) || path.Any(char.IsControl) || path.Contains('\\') || path.Contains("//", StringComparison.Ordinal)) return false;
        if (path.Contains('%')) return false;
        return path.Split('/').All(segment => segment is not ("." or ".."));
    }

    private static int EffectivePort(Uri uri) => uri.IsDefaultPort ? (uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80) : uri.Port;

    private static string NormalizeRepositoryPath(string path) => path.Trim('/').TrimEnd('/').Replace(".git", string.Empty, StringComparison.OrdinalIgnoreCase);

    public static bool IsPrivateAddress(IPAddress address)
    {
        address = NormalizeAddress(address);
        return IsWithinNetwork(address, "10.0.0.0/8") || IsWithinNetwork(address, "172.16.0.0/12") || IsWithinNetwork(address, "192.168.0.0/16") || IsWithinNetwork(address, "fc00::/7");
    }

    public static bool IsDisallowedAddress(IPAddress address)
    {
        address = NormalizeAddress(address);
        return address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || IPAddress.IsLoopback(address) ||
           IsWithinNetwork(address, "0.0.0.0/8") || IsWithinNetwork(address, "100.64.0.0/10") || IsWithinNetwork(address, "169.254.0.0/16") || IsWithinNetwork(address, "192.0.0.0/24") || IsWithinNetwork(address, "192.0.2.0/24") || IsWithinNetwork(address, "192.88.99.0/24") ||
           IsWithinNetwork(address, "198.18.0.0/15") || IsWithinNetwork(address, "198.51.100.0/24") || IsWithinNetwork(address, "203.0.113.0/24") ||
           IsWithinNetwork(address, "224.0.0.0/4") || IsWithinNetwork(address, "240.0.0.0/4") ||
           IsWithinNetwork(address, "::/128") || IsWithinNetwork(address, "::1/128") || IsWithinNetwork(address, "100::/64") || IsWithinNetwork(address, "64:ff9b::/96") ||
           IsWithinNetwork(address, "2001::/32") || IsWithinNetwork(address, "2001:2::/48") || IsWithinNetwork(address, "2001:10::/28") || IsWithinNetwork(address, "2001:20::/28") ||
           IsWithinNetwork(address, "2001:db8::/32") || IsWithinNetwork(address, "2002::/16") || IsWithinNetwork(address, "fe80::/10") || IsWithinNetwork(address, "ff00::/8");
    }

    internal static bool IsWithinNetwork(IPAddress address, string definition)
    {
        address = NormalizeAddress(address);
        if (!TryParseCidr(definition, out var network, out var prefix) || network.AddressFamily != address.AddressFamily) return false;
        var networkBytes = network.GetAddressBytes(); var addressBytes = address.GetAddressBytes();
        var fullBytes = prefix / 8; var remainingBits = prefix % 8;
        for (var i = 0; i < fullBytes; i++) if (networkBytes[i] != addressBytes[i]) return false;
        return remainingBits == 0 || (networkBytes[fullBytes] & (byte)(0xFF << (8 - remainingBits))) == (addressBytes[fullBytes] & (byte)(0xFF << (8 - remainingBits)));
    }

    private static ValidatedExecutionTarget CreateValidatedTarget(string hostname, IReadOnlyCollection<IPAddress> addresses, TargetScope scope, string operationProfile)
        => new(hostname, addresses.Select(NormalizeAddress).Distinct().ToArray(), DateTimeOffset.UtcNow, scope.Id, scope.TenantId, scope.ExpiresAt, operationProfile);

    private static IPAddress NormalizeAddress(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    public static bool IsValidPrivateNetworkRange(string value)
        => TryParseCidr(value.Trim(), out _, out _) && CidrContainedByAny(value.Trim(), ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]) && !CidrIntersectsDisallowed(value.Trim());

    public static bool IsNetworkRangeContainedBy(string candidate, string approved) => CidrContains(approved.Trim(), candidate.Trim());
}
