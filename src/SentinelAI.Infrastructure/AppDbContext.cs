using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Application;
using SentinelAI.Domain;

namespace SentinelAI.Infrastructure;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options), IAppDbContext
{
    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<User> Users => Set<User>();
    public DbSet<TargetScope> TargetScopes => Set<TargetScope>();
    public DbSet<ScanPolicy> ScanPolicies => Set<ScanPolicy>();
    public DbSet<AgentJob> AgentJobs => Set<AgentJob>();
    public DbSet<AgentExecution> AgentExecutions => Set<AgentExecution>();
    public DbSet<Asset> Assets => Set<Asset>();
    public DbSet<AssetService> AssetServices => Set<AssetService>();
    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<Evidence> Evidence => Set<Evidence>();
    public DbSet<ApprovalRequest> ApprovalRequests => Set<ApprovalRequest>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<AIAnalysis> AIAnalyses => Set<AIAnalysis>();
    public DbSet<Notification> Notifications => Set<Notification>();
    public DbSet<WorkerRegistration> Workers => Set<WorkerRegistration>();
    public DbSet<PublicTargetAuthorization> PublicTargetAuthorizations => Set<PublicTargetAuthorization>();
    public DbSet<OutboxMessage> OutboxMessages => Set<OutboxMessage>();
    public DbSet<WebAssessment> WebAssessments => Set<WebAssessment>();
    public DbSet<WebAssessmentEndpoint> WebAssessmentEndpoints => Set<WebAssessmentEndpoint>();
    public DbSet<AssessmentScreenshot> AssessmentScreenshots => Set<AssessmentScreenshot>();
    public DbSet<WebAssessmentCheck> WebAssessmentChecks => Set<WebAssessmentCheck>();
    public DbSet<VulnerabilityCatalogEntry> VulnerabilityCatalogEntries => Set<VulnerabilityCatalogEntry>();
    public DbSet<VulnerabilityCvssMetric> VulnerabilityCvssMetrics => Set<VulnerabilityCvssMetric>();
    public DbSet<VulnerabilityKevEntry> VulnerabilityKevEntries => Set<VulnerabilityKevEntry>();
    public DbSet<VulnerabilityEpssScore> VulnerabilityEpssScores => Set<VulnerabilityEpssScore>();
    public DbSet<VulnerabilitySyncCheckpoint> VulnerabilitySyncCheckpoints => Set<VulnerabilitySyncCheckpoint>();
    public DbSet<SoftwareComponent> SoftwareComponents => Set<SoftwareComponent>();
    public DbSet<AssetVulnerabilityMatch> AssetVulnerabilityMatches => Set<AssetVulnerabilityMatch>();

    public async Task PersistWebAssessmentEndpointsAsync(Guid tenantId, Guid assessmentId, IReadOnlyCollection<WebAssessmentEndpoint> endpoints, CancellationToken cancellationToken = default)
    {
        if (endpoints.Count == 0) return;
        if (endpoints.Any(endpoint => endpoint.TenantId != tenantId || endpoint.AssessmentId != assessmentId))
            throw new ArgumentException("All web assessment endpoints must belong to the supplied tenant and assessment.", nameof(endpoints));

        var distinct = endpoints
            .GroupBy(endpoint => endpoint.Url, StringComparer.Ordinal)
            .Select(group => group.First())
            .ToArray();

        if (distinct.Length == 0) return;

        if (Database.ProviderName?.Contains("Npgsql", StringComparison.OrdinalIgnoreCase) == true)
        {
            foreach (var endpoint in distinct)
            {
                await Database.ExecuteSqlInterpolatedAsync($"""
                    INSERT INTO "WebAssessmentEndpoints" ("Id", "TenantId", "AssessmentId", "Url", "Method", "Depth", "Kind", "DiscoveredAt")
                    VALUES ({endpoint.Id}, {endpoint.TenantId}, {endpoint.AssessmentId}, {endpoint.Url}, {endpoint.Method}, {endpoint.Depth}, {endpoint.Kind}, {endpoint.DiscoveredAt})
                    ON CONFLICT ("TenantId", "AssessmentId", "Url") DO NOTHING
                    """, cancellationToken);
            }

            return;
        }

        var urls = distinct.Select(endpoint => endpoint.Url).ToArray();
        var existing = await WebAssessmentEndpoints.AsNoTracking()
            .Where(endpoint => endpoint.TenantId == tenantId && endpoint.AssessmentId == assessmentId && urls.Contains(endpoint.Url))
            .Select(endpoint => endpoint.Url)
            .ToListAsync(cancellationToken);
        var existingUrls = existing.ToHashSet(StringComparer.Ordinal);
        foreach (var endpoint in distinct.Where(endpoint => existingUrls.Add(endpoint.Url)))
            WebAssessmentEndpoints.Add(endpoint);
        await SaveChangesAsync(cancellationToken);
    }

    public async Task<IAppDbTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
    {
        if (Database.ProviderName?.Contains("InMemory", StringComparison.OrdinalIgnoreCase) == true)
            return new NoopAppDbTransaction();
        return new EfAppDbTransaction(await Database.BeginTransactionAsync(cancellationToken));
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.Entity<Tenant>().HasKey(x => x.Id);
        modelBuilder.Entity<User>().HasKey(x => x.Id);
        modelBuilder.Entity<TargetScope>().HasKey(x => x.Id);
        modelBuilder.Entity<ScanPolicy>().HasKey(x => x.Id);
        modelBuilder.Entity<AgentJob>().HasKey(x => x.Id);
        modelBuilder.Entity<AgentExecution>().HasKey(x => x.Id);
        modelBuilder.Entity<Asset>().HasKey(x => x.Id);
        modelBuilder.Entity<AssetService>().HasKey(x => x.Id);
        modelBuilder.Entity<Finding>().HasKey(x => x.Id);
        modelBuilder.Entity<Evidence>().HasKey(x => x.Id);
        modelBuilder.Entity<ApprovalRequest>().HasKey(x => x.Id);
        modelBuilder.Entity<AuditEvent>().HasKey(x => x.Id);
        modelBuilder.Entity<AIAnalysis>().HasKey(x => x.Id);
        modelBuilder.Entity<Notification>().HasKey(x => x.Id);
        modelBuilder.Entity<WorkerRegistration>().HasKey(x => x.Id);
        modelBuilder.Entity<PublicTargetAuthorization>().HasKey(x => x.Id);
        modelBuilder.Entity<OutboxMessage>().HasKey(x => x.Id);
        modelBuilder.Entity<WebAssessment>().HasKey(x => x.Id);
        modelBuilder.Entity<WebAssessmentEndpoint>().HasKey(x => x.Id);
        modelBuilder.Entity<AssessmentScreenshot>().HasKey(x => x.Id);
        modelBuilder.Entity<WebAssessmentCheck>().HasKey(x => x.Id);
        modelBuilder.Entity<VulnerabilityCatalogEntry>().HasKey(x => x.CveId);
        modelBuilder.Entity<VulnerabilityCvssMetric>().HasKey(x => x.Id);
        modelBuilder.Entity<VulnerabilityKevEntry>().HasKey(x => x.CveId);
        modelBuilder.Entity<VulnerabilityEpssScore>().HasKey(x => x.Id);
        modelBuilder.Entity<VulnerabilitySyncCheckpoint>().HasKey(x => x.Id);
        modelBuilder.Entity<SoftwareComponent>().HasKey(x => x.Id);
        modelBuilder.Entity<AssetVulnerabilityMatch>().HasKey(x => x.Id);

        ConfigureTenant(modelBuilder.Entity<User>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<TargetScope>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<ScanPolicy>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<AgentJob>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<Asset>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<AssetService>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<Finding>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<Evidence>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<ApprovalRequest>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<AuditEvent>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<AIAnalysis>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<Notification>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<WorkerRegistration>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<PublicTargetAuthorization>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<OutboxMessage>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<WebAssessment>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<WebAssessmentEndpoint>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<AssessmentScreenshot>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<WebAssessmentCheck>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<SoftwareComponent>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<AssetVulnerabilityMatch>().Property(x => x.TenantId));

        var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        var targetComparer = new ValueComparer<List<TargetDefinition>>((a, b) => JsonSerializer.Serialize(a, jsonOptions) == JsonSerializer.Serialize(b, jsonOptions), v => v.Aggregate(0, (hash, item) => HashCode.Combine(hash, item.GetHashCode())), v => v.ToList());
        var stringComparer = new ValueComparer<List<string>>((a, b) => JsonSerializer.Serialize(a, jsonOptions) == JsonSerializer.Serialize(b, jsonOptions), v => v.Aggregate(0, (hash, item) => HashCode.Combine(hash, item.GetHashCode())), v => v.ToList());
        var scope = modelBuilder.Entity<TargetScope>();
        scope.Property(x => x.Targets).HasConversion(v => JsonSerializer.Serialize(v, jsonOptions), v => DeserializeList<TargetDefinition>(v, jsonOptions)).Metadata.SetValueComparer(targetComparer);
        scope.Property(x => x.Exclusions).HasConversion(v => JsonSerializer.Serialize(v, jsonOptions), v => DeserializeList<string>(v, jsonOptions)).Metadata.SetValueComparer(stringComparer);
        scope.Property(x => x.ApprovedOperationProfiles).HasConversion(v => JsonSerializer.Serialize(v, jsonOptions), v => DeserializeList<string>(v, jsonOptions)).Metadata.SetValueComparer(stringComparer);
        scope.Property(x => x.PublicTargetVerifications).HasConversion(v => JsonSerializer.Serialize(v, jsonOptions), v => DeserializeList<PublicTargetVerification>(v, jsonOptions)).Metadata.SetValueComparer(new ValueComparer<List<PublicTargetVerification>>((a, b) => JsonSerializer.Serialize(a, jsonOptions) == JsonSerializer.Serialize(b, jsonOptions), v => v.Aggregate(0, (hash, item) => HashCode.Combine(hash, item.GetHashCode())), v => v.ToList()));
        scope.Property(x => x.ApprovedPrivateNetworkRanges).HasConversion(v => JsonSerializer.Serialize(v, jsonOptions), v => DeserializeList<string>(v, jsonOptions)).Metadata.SetValueComparer(stringComparer);
        modelBuilder.Entity<WorkerRegistration>().Property(x => x.Capabilities).HasConversion(v => JsonSerializer.Serialize(v, jsonOptions), v => DeserializeList<string>(v, jsonOptions)).Metadata.SetValueComparer(stringComparer);
        modelBuilder.Entity<WorkerRegistration>().Property(x => x.ApprovedPrivateNetworkRanges).HasConversion(v => JsonSerializer.Serialize(v, jsonOptions), v => DeserializeList<string>(v, jsonOptions)).Metadata.SetValueComparer(stringComparer);

        modelBuilder.Entity<Tenant>().Property<byte[]>("RowVersion").IsConcurrencyToken();
        modelBuilder.Entity<TargetScope>().Property<byte[]>("RowVersion").IsConcurrencyToken();
        modelBuilder.Entity<AgentJob>().Property<byte[]>("RowVersion").IsConcurrencyToken();
        modelBuilder.Entity<Tenant>().HasIndex(x => x.Name).IsUnique();
        modelBuilder.Entity<TargetScope>().HasIndex(x => new { x.TenantId, x.ExpiresAt });
        modelBuilder.Entity<AgentJob>().HasIndex(x => new { x.TenantId, x.Status, x.CreatedAt });
        modelBuilder.Entity<AgentJob>().HasIndex(x => new { x.Status, x.LeaseExpiresAt });
        modelBuilder.Entity<Asset>().HasIndex(x => new { x.TenantId, x.Address }).IsUnique();
        modelBuilder.Entity<Asset>().HasAlternateKey(x => new { x.TenantId, x.Id });
        modelBuilder.Entity<AssetService>().HasIndex(x => new { x.TenantId, x.AssetId, x.Protocol, x.Port }).IsUnique();
        modelBuilder.Entity<AssetService>().HasOne<Asset>().WithMany().HasForeignKey(x => new { x.TenantId, x.AssetId }).HasPrincipalKey(x => new { x.TenantId, x.Id }).OnDelete(DeleteBehavior.Cascade);
        modelBuilder.Entity<Finding>().HasIndex(x => new { x.TenantId, x.Severity });
        modelBuilder.Entity<AuditEvent>().HasIndex(x => new { x.TenantId, x.OccurredAt });
        modelBuilder.Entity<WorkerRegistration>().HasIndex(x => new { x.TenantId, x.Identity }).IsUnique();
        modelBuilder.Entity<PublicTargetAuthorization>().HasIndex(x => new { x.TenantId, x.Target, x.Status });
        modelBuilder.Entity<OutboxMessage>().HasIndex(x => new { x.DispatchedAt, x.NextAttemptAt, x.LeaseExpiresAt, x.CreatedAt });
        modelBuilder.Entity<WebAssessment>().HasIndex(x => new { x.TenantId, x.CreatedAt });
        modelBuilder.Entity<WebAssessment>().HasIndex(x => new { x.TenantId, x.AgentJobId }).IsUnique();
        modelBuilder.Entity<WebAssessmentEndpoint>().HasIndex(x => new { x.TenantId, x.AssessmentId, x.Url }).IsUnique();
        modelBuilder.Entity<AssessmentScreenshot>().HasIndex(x => new { x.TenantId, x.AssessmentId, x.Id });
        modelBuilder.Entity<WebAssessmentCheck>().HasIndex(x => new { x.TenantId, x.AssessmentId, x.CheckId, x.AffectedEndpoint }).IsUnique();
        modelBuilder.Entity<Finding>().HasIndex(x => new { x.TenantId, x.AssessmentId, x.IdempotencyKey }).IsUnique();
        modelBuilder.Entity<VulnerabilityCatalogEntry>().Property(x => x.CveId).HasMaxLength(20);
        modelBuilder.Entity<VulnerabilityCvssMetric>().Property(x => x.CveId).HasMaxLength(20);
        modelBuilder.Entity<VulnerabilityKevEntry>().Property(x => x.CveId).HasMaxLength(20);
        modelBuilder.Entity<VulnerabilityEpssScore>().Property(x => x.CveId).HasMaxLength(20);
        modelBuilder.Entity<AssetVulnerabilityMatch>().Property(x => x.CveId).HasMaxLength(20);
        modelBuilder.Entity<VulnerabilityCatalogEntry>().HasIndex(x => x.LastModifiedAt);
        modelBuilder.Entity<VulnerabilityCvssMetric>().HasIndex(x => new { x.CveId, x.Version, x.Vector, x.Source }).IsUnique();
        modelBuilder.Entity<VulnerabilityCvssMetric>().HasOne<VulnerabilityCatalogEntry>().WithMany()
            .HasForeignKey(x => x.CveId).HasPrincipalKey(x => x.CveId).OnDelete(DeleteBehavior.Cascade);
        modelBuilder.Entity<VulnerabilityKevEntry>().HasIndex(x => new { x.IsListed, x.DueDate });
        modelBuilder.Entity<VulnerabilityEpssScore>().HasIndex(x => new { x.CveId, x.AsOfDate }).IsUnique();
        modelBuilder.Entity<VulnerabilitySyncCheckpoint>().HasIndex(x => x.Source).IsUnique();
        modelBuilder.Entity<SoftwareComponent>().HasAlternateKey(x => new { x.TenantId, x.Id });
        modelBuilder.Entity<SoftwareComponent>().HasIndex(x => new { x.TenantId, x.AssetId, x.CpeName, x.Version }).IsUnique();
        modelBuilder.Entity<SoftwareComponent>().HasOne<Asset>().WithMany()
            .HasForeignKey(x => new { x.TenantId, x.AssetId }).HasPrincipalKey(x => new { x.TenantId, x.Id }).OnDelete(DeleteBehavior.Cascade);
        modelBuilder.Entity<AssetVulnerabilityMatch>().HasIndex(x => new { x.TenantId, x.SoftwareComponentId, x.CveId }).IsUnique();
        modelBuilder.Entity<AssetVulnerabilityMatch>().HasOne<SoftwareComponent>().WithMany()
            .HasForeignKey(x => new { x.TenantId, x.SoftwareComponentId }).HasPrincipalKey(x => new { x.TenantId, x.Id }).OnDelete(DeleteBehavior.Cascade);
        modelBuilder.Entity<AssetVulnerabilityMatch>().HasOne<VulnerabilityCatalogEntry>().WithMany()
            .HasForeignKey(x => x.CveId).HasPrincipalKey(x => x.CveId).OnDelete(DeleteBehavior.Restrict);
    }

    private static void ConfigureTenant(PropertyBuilder<Guid> property) => property.IsRequired();

    private static List<T> DeserializeList<T>(string? json, JsonSerializerOptions opts) =>
        string.IsNullOrWhiteSpace(json) ? [] : JsonSerializer.Deserialize<List<T>>(json, opts) ?? [];

    private sealed class NoopAppDbTransaction : IAppDbTransaction
    {
        public Task CommitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class EfAppDbTransaction(Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction) : IAppDbTransaction
    {
        public Task CommitAsync(CancellationToken cancellationToken = default) => transaction.CommitAsync(cancellationToken);
        public ValueTask DisposeAsync() => transaction.DisposeAsync();
    }
}
