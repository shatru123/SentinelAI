namespace SentinelAI.Domain;

public sealed class FindingAIAnalysis
{
    private FindingAIAnalysis() { }

    public FindingAIAnalysis(Guid tenantId, Guid findingId, Guid actorId, string provider, string model,
        string promptTemplateVersion, string evidenceSha256, string summary, string resultJson,
        int? inputTokens, int? outputTokens, string? responseId, string? finishReason)
    {
        if (tenantId == Guid.Empty || findingId == Guid.Empty || actorId == Guid.Empty)
            throw new ArgumentException("Tenant, finding and actor identifiers are required.");
        Id = Guid.NewGuid(); TenantId = tenantId; FindingId = findingId; ActorId = actorId;
        Provider = Required(provider, 64, nameof(provider));
        Model = Required(model, 128, nameof(model));
        PromptTemplateVersion = Required(promptTemplateVersion, 64, nameof(promptTemplateVersion));
        EvidenceSha256 = Required(evidenceSha256, 64, nameof(evidenceSha256));
        if (EvidenceSha256.Length != 64 || EvidenceSha256.Any(character => !Uri.IsHexDigit(character)))
            throw new ArgumentException("Evidence hash must be hexadecimal SHA-256.", nameof(evidenceSha256));
        Summary = Required(summary, 2_000, nameof(summary));
        ResultJson = Required(resultJson, 24_000, nameof(resultJson));
        if (inputTokens is < 0 || outputTokens is < 0) throw new ArgumentOutOfRangeException(nameof(inputTokens));
        InputTokens = inputTokens; OutputTokens = outputTokens;
        ResponseId = Optional(responseId, 256, nameof(responseId));
        FinishReason = Optional(finishReason, 64, nameof(finishReason));
        CreatedAt = DateTimeOffset.UtcNow;
    }

    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid FindingId { get; private set; }
    public Guid ActorId { get; private set; }
    public string Provider { get; private set; } = string.Empty;
    public string Model { get; private set; } = string.Empty;
    public string PromptTemplateVersion { get; private set; } = string.Empty;
    public string EvidenceSha256 { get; private set; } = string.Empty;
    public string Summary { get; private set; } = string.Empty;
    public string ResultJson { get; private set; } = string.Empty;
    public int? InputTokens { get; private set; }
    public int? OutputTokens { get; private set; }
    public string? ResponseId { get; private set; }
    public string? FinishReason { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }

    private static string Required(string? value, int max, string name)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > max)
            throw new ArgumentException($"A non-empty value of at most {max} characters is required.", name);
        return value.Trim();
    }

    private static string? Optional(string? value, int max, string name)
    {
        if (value is null) return null;
        if (value.Length > max) throw new ArgumentException($"The value cannot exceed {max} characters.", name);
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }
}
