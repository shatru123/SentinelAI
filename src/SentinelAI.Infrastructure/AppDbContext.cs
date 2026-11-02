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
    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<Evidence> Evidence => Set<Evidence>();
    public DbSet<ApprovalRequest> ApprovalRequests => Set<ApprovalRequest>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<AIAnalysis> AIAnalyses => Set<AIAnalysis>();
    public DbSet<Notification> Notifications => Set<Notification>();

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
        modelBuilder.Entity<Finding>().HasKey(x => x.Id);
        modelBuilder.Entity<Evidence>().HasKey(x => x.Id);
        modelBuilder.Entity<ApprovalRequest>().HasKey(x => x.Id);
        modelBuilder.Entity<AuditEvent>().HasKey(x => x.Id);
        modelBuilder.Entity<AIAnalysis>().HasKey(x => x.Id);
        modelBuilder.Entity<Notification>().HasKey(x => x.Id);

        ConfigureTenant(modelBuilder.Entity<User>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<TargetScope>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<ScanPolicy>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<AgentJob>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<Asset>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<Finding>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<Evidence>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<ApprovalRequest>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<AuditEvent>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<AIAnalysis>().Property(x => x.TenantId));
        ConfigureTenant(modelBuilder.Entity<Notification>().Property(x => x.TenantId));

        var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        var targetComparer = new ValueComparer<List<TargetDefinition>>((a, b) => JsonSerializer.Serialize(a, jsonOptions) == JsonSerializer.Serialize(b, jsonOptions), v => v.Aggregate(0, (hash, item) => HashCode.Combine(hash, item.GetHashCode())), v => v.ToList());
        var stringComparer = new ValueComparer<List<string>>((a, b) => JsonSerializer.Serialize(a, jsonOptions) == JsonSerializer.Serialize(b, jsonOptions), v => v.Aggregate(0, (hash, item) => HashCode.Combine(hash, item.GetHashCode())), v => v.ToList());
        var scope = modelBuilder.Entity<TargetScope>();
        scope.Property(x => x.Targets).HasConversion(v => JsonSerializer.Serialize(v, jsonOptions), v => JsonSerializer.Deserialize<List<TargetDefinition>>(v, jsonOptions) ?? new List<TargetDefinition>()).Metadata.SetValueComparer(targetComparer);
        scope.Property(x => x.Exclusions).HasConversion(v => JsonSerializer.Serialize(v, jsonOptions), v => JsonSerializer.Deserialize<List<string>>(v, jsonOptions) ?? new List<string>()).Metadata.SetValueComparer(stringComparer);
        scope.Property(x => x.ApprovedOperationProfiles).HasConversion(v => JsonSerializer.Serialize(v, jsonOptions), v => JsonSerializer.Deserialize<List<string>>(v, jsonOptions) ?? new List<string>()).Metadata.SetValueComparer(stringComparer);

        modelBuilder.Entity<Tenant>().Property<byte[]>("RowVersion").IsConcurrencyToken();
        modelBuilder.Entity<TargetScope>().Property<byte[]>("RowVersion").IsConcurrencyToken();
        modelBuilder.Entity<AgentJob>().Property<byte[]>("RowVersion").IsConcurrencyToken();
        modelBuilder.Entity<Tenant>().HasIndex(x => x.Name).IsUnique();
        modelBuilder.Entity<TargetScope>().HasIndex(x => new { x.TenantId, x.ExpiresAt });
        modelBuilder.Entity<AgentJob>().HasIndex(x => new { x.TenantId, x.Status, x.CreatedAt });
        modelBuilder.Entity<Asset>().HasIndex(x => new { x.TenantId, x.Address }).IsUnique();
        modelBuilder.Entity<Finding>().HasIndex(x => new { x.TenantId, x.Severity });
        modelBuilder.Entity<AuditEvent>().HasIndex(x => new { x.TenantId, x.OccurredAt });
    }

    private static void ConfigureTenant(PropertyBuilder<Guid> property) => property.IsRequired();
}
