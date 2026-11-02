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

        var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        var targetComparer = new ValueComparer<List<TargetDefinition>>((a, b) => JsonSerializer.Serialize(a, jsonOptions) == JsonSerializer.Serialize(b, jsonOptions), v => v.Aggregate(0, (hash, item) => HashCode.Combine(hash, item.GetHashCode())), v => v.ToList());
        var stringComparer = new ValueComparer<List<string>>((a, b) => JsonSerializer.Serialize(a, jsonOptions) == JsonSerializer.Serialize(b, jsonOptions), v => v.Aggregate(0, (hash, item) => HashCode.Combine(hash, item.GetHashCode())), v => v.ToList());
        var scope = modelBuilder.Entity<TargetScope>();
        scope.Property(x => x.Targets).HasConversion(v => JsonSerializer.Serialize(v, jsonOptions), v => JsonSerializer.Deserialize<List<TargetDefinition>>(v, jsonOptions) ?? new List<TargetDefinition>()).Metadata.SetValueComparer(targetComparer);
        scope.Property(x => x.Exclusions).HasConversion(v => JsonSerializer.Serialize(v, jsonOptions), v => JsonSerializer.Deserialize<List<string>>(v, jsonOptions) ?? new List<string>()).Metadata.SetValueComparer(stringComparer);
        scope.Property(x => x.ApprovedOperationProfiles).HasConversion(v => JsonSerializer.Serialize(v, jsonOptions), v => JsonSerializer.Deserialize<List<string>>(v, jsonOptions) ?? new List<string>()).Metadata.SetValueComparer(stringComparer);
        scope.Property(x => x.PublicTargetVerifications).HasConversion(v => JsonSerializer.Serialize(v, jsonOptions), v => JsonSerializer.Deserialize<List<PublicTargetVerification>>(v, jsonOptions) ?? new List<PublicTargetVerification>()).Metadata.SetValueComparer(new ValueComparer<List<PublicTargetVerification>>((a, b) => JsonSerializer.Serialize(a, jsonOptions) == JsonSerializer.Serialize(b, jsonOptions), v => v.Aggregate(0, (hash, item) => HashCode.Combine(hash, item.GetHashCode())), v => v.ToList()));
        modelBuilder.Entity<WorkerRegistration>().Property(x => x.Capabilities).HasConversion(v => JsonSerializer.Serialize(v, jsonOptions), v => JsonSerializer.Deserialize<List<string>>(v, jsonOptions) ?? new List<string>()).Metadata.SetValueComparer(stringComparer);

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
    }

    private static void ConfigureTenant(PropertyBuilder<Guid> property) => property.IsRequired();

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
