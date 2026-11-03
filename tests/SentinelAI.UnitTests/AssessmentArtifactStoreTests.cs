using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;

namespace SentinelAI.UnitTests;

public sealed class AssessmentArtifactStoreTests
{
    [Fact]
    public async Task Staged_report_is_not_retrievable_until_published_and_tenant_assessment_boundaries_hold()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-artifacts-{Guid.NewGuid():N}");
        var tenantA = Guid.NewGuid();
        var tenantB = Guid.NewGuid();
        var assessmentA = Guid.NewGuid();
        var assessmentB = Guid.NewGuid();
        try
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Artifacts:Root"] = root }).Build();
            var store = new FileSystemAssessmentArtifactStore(configuration);
            var bytes = new byte[] { 60, 104, 49, 62 };

            var staged = await store.StageReportAsync(tenantA, assessmentA, bytes, CancellationToken.None);
            Assert.Null(await store.GetPublishedReportAsync(tenantA, assessmentA, staged, CancellationToken.None));
            Assert.Null(await store.GetAsync(tenantA, staged, CancellationToken.None));

            var published = await store.PublishReportAsync(tenantA, assessmentA, staged, CancellationToken.None);
            Assert.Equal(bytes, await store.GetPublishedReportAsync(tenantA, assessmentA, published, CancellationToken.None));
            Assert.Null(await store.GetPublishedReportAsync(tenantB, assessmentA, published, CancellationToken.None));
            Assert.Null(await store.GetPublishedReportAsync(tenantA, assessmentB, published, CancellationToken.None));
            Assert.Null(await store.GetPublishedReportAsync(tenantA, assessmentA, staged, CancellationToken.None));

            await store.DiscardReportAsync(tenantA, assessmentA, published, CancellationToken.None);
            Assert.Null(await store.GetPublishedReportAsync(tenantA, assessmentA, published, CancellationToken.None));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Abandoned_staged_reports_are_bounded_and_cleaned_without_touching_published_reports()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-artifacts-{Guid.NewGuid():N}");
        var tenant = Guid.NewGuid();
        var assessment = Guid.NewGuid();
        try
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Artifacts:Root"] = root }).Build();
            var store = new FileSystemAssessmentArtifactStore(configuration);
            var oldStaged = await store.StageReportAsync(tenant, assessment, [1, 2, 3], CancellationToken.None);
            var publishedStaged = await store.StageReportAsync(tenant, assessment, [4, 5, 6], CancellationToken.None);
            var published = await store.PublishReportAsync(tenant, assessment, publishedStaged, CancellationToken.None);
            File.SetLastWriteTimeUtc(Path.Combine(root, oldStaged.Replace('/', Path.DirectorySeparatorChar)), DateTime.UtcNow.AddHours(-2));

            var removed = await store.CleanupStagedReportsAsync(DateTimeOffset.UtcNow.AddHours(-1), CancellationToken.None);

            Assert.Equal(1, removed);
            Assert.Null(await store.GetPublishedReportAsync(tenant, assessment, oldStaged, CancellationToken.None));
            Assert.Equal(new byte[] { 4, 5, 6 }, await store.GetPublishedReportAsync(tenant, assessment, published, CancellationToken.None));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Old_published_report_without_database_reference_is_reconciled_and_removed()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-artifacts-{Guid.NewGuid():N}");
        var tenant = Guid.NewGuid();
        var assessment = Guid.NewGuid();
        try
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Artifacts:Root"] = root }).Build();
            var store = new FileSystemAssessmentArtifactStore(configuration);
            var staged = await store.StageReportAsync(tenant, assessment, [1, 2, 3], CancellationToken.None);
            var published = await store.PublishReportAsync(tenant, assessment, staged, CancellationToken.None);
            File.SetLastWriteTimeUtc(Path.Combine(root, published.Replace('/', Path.DirectorySeparatorChar)), DateTime.UtcNow.AddHours(-3));

            var removed = await store.ReconcilePublishedReportsAsync(DateTimeOffset.UtcNow.AddHours(-2), _ => Task.FromResult(false), CancellationToken.None);

            Assert.Equal(1, removed);
            Assert.Null(await store.GetPublishedReportAsync(tenant, assessment, published, CancellationToken.None));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Published_report_referenced_by_completed_assessment_is_preserved()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-artifacts-{Guid.NewGuid():N}");
        var tenant = Guid.NewGuid();
        var assessment = Guid.NewGuid();
        try
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Artifacts:Root"] = root }).Build();
            var store = new FileSystemAssessmentArtifactStore(configuration);
            var staged = await store.StageReportAsync(tenant, assessment, [1, 2, 3], CancellationToken.None);
            var published = await store.PublishReportAsync(tenant, assessment, staged, CancellationToken.None);
            File.SetLastWriteTimeUtc(Path.Combine(root, published.Replace('/', Path.DirectorySeparatorChar)), DateTime.UtcNow.AddHours(-3));

            var removed = await store.ReconcilePublishedReportsAsync(DateTimeOffset.UtcNow.AddHours(-2), key => Task.FromResult(string.Equals(key, published, StringComparison.OrdinalIgnoreCase)), CancellationToken.None);

            Assert.Equal(0, removed);
            Assert.Equal(new byte[] { 1, 2, 3 }, await store.GetPublishedReportAsync(tenant, assessment, published, CancellationToken.None));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Newly_published_report_is_preserved_during_grace_period()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-artifacts-{Guid.NewGuid():N}");
        var tenant = Guid.NewGuid();
        var assessment = Guid.NewGuid();
        try
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Artifacts:Root"] = root }).Build();
            var store = new FileSystemAssessmentArtifactStore(configuration);
            var staged = await store.StageReportAsync(tenant, assessment, [1, 2, 3], CancellationToken.None);
            var published = await store.PublishReportAsync(tenant, assessment, staged, CancellationToken.None);

            // Report written just now - not older than 2 hours
            var removed = await store.ReconcilePublishedReportsAsync(DateTimeOffset.UtcNow.AddHours(-2), _ => Task.FromResult(false), CancellationToken.None);

            Assert.Equal(0, removed);
            Assert.Equal(new byte[] { 1, 2, 3 }, await store.GetPublishedReportAsync(tenant, assessment, published, CancellationToken.None));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Unrelated_files_and_screenshots_are_never_removed()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-artifacts-{Guid.NewGuid():N}");
        var tenant = Guid.NewGuid();
        var assessment = Guid.NewGuid();
        try
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Artifacts:Root"] = root }).Build();
            var store = new FileSystemAssessmentArtifactStore(configuration);
            var screenshotKey = await store.PutAsync(tenant, assessment, "screenshot.png", [137, 80, 78, 71], CancellationToken.None);

            var tenantDir = Path.Combine(root, tenant.ToString());
            var assessmentDir = Path.Combine(tenantDir, assessment.ToString());
            Directory.CreateDirectory(assessmentDir);

            var notesPath = Path.Combine(tenantDir, "notes.txt");
            var dataJsonPath = Path.Combine(assessmentDir, "data.json");
            await File.WriteAllTextAsync(notesPath, "tenant notes");
            await File.WriteAllTextAsync(dataJsonPath, "{\"key\":\"value\"}");

            File.SetLastWriteTimeUtc(Path.Combine(root, screenshotKey.Replace('/', Path.DirectorySeparatorChar)), DateTime.UtcNow.AddHours(-5));
            File.SetLastWriteTimeUtc(notesPath, DateTime.UtcNow.AddHours(-5));
            File.SetLastWriteTimeUtc(dataJsonPath, DateTime.UtcNow.AddHours(-5));

            var removed = await store.ReconcilePublishedReportsAsync(DateTimeOffset.UtcNow.AddHours(-1), _ => Task.FromResult(false), CancellationToken.None);

            Assert.Equal(0, removed);
            Assert.True(File.Exists(notesPath));
            Assert.True(File.Exists(dataJsonPath));
            Assert.NotNull(await store.GetAsync(tenant, screenshotKey, CancellationToken.None));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Tenant_and_assessment_boundaries_are_respected_during_reconciliation()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-artifacts-{Guid.NewGuid():N}");
        var tenantA = Guid.NewGuid();
        var tenantB = Guid.NewGuid();
        var assessmentA = Guid.NewGuid();
        var assessmentB = Guid.NewGuid();
        try
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Artifacts:Root"] = root }).Build();
            var store = new FileSystemAssessmentArtifactStore(configuration);

            var stagedA = await store.StageReportAsync(tenantA, assessmentA, [1, 1, 1], CancellationToken.None);
            var publishedA = await store.PublishReportAsync(tenantA, assessmentA, stagedA, CancellationToken.None);

            var stagedB = await store.StageReportAsync(tenantB, assessmentB, [2, 2, 2], CancellationToken.None);
            var publishedB = await store.PublishReportAsync(tenantB, assessmentB, stagedB, CancellationToken.None);

            File.SetLastWriteTimeUtc(Path.Combine(root, publishedA.Replace('/', Path.DirectorySeparatorChar)), DateTime.UtcNow.AddHours(-3));
            File.SetLastWriteTimeUtc(Path.Combine(root, publishedB.Replace('/', Path.DirectorySeparatorChar)), DateTime.UtcNow.AddHours(-3));

            // Only tenantA's report is referenced
            var removed = await store.ReconcilePublishedReportsAsync(
                DateTimeOffset.UtcNow.AddHours(-2),
                key => Task.FromResult(key.StartsWith(tenantA.ToString(), StringComparison.OrdinalIgnoreCase)),
                CancellationToken.None);

            Assert.Equal(1, removed);
            Assert.Equal(new byte[] { 1, 1, 1 }, await store.GetPublishedReportAsync(tenantA, assessmentA, publishedA, CancellationToken.None));
            Assert.Null(await store.GetPublishedReportAsync(tenantB, assessmentB, publishedB, CancellationToken.None));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Concurrent_cleanup_attempts_do_not_corrupt_files()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-artifacts-{Guid.NewGuid():N}");
        var tenant = Guid.NewGuid();
        var assessments = new List<Guid>();
        var publishedKeys = new List<string>();
        try
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Artifacts:Root"] = root }).Build();
            var store = new FileSystemAssessmentArtifactStore(configuration);

            for (var i = 0; i < 5; i++)
            {
                var assessment = Guid.NewGuid();
                assessments.Add(assessment);
                var staged = await store.StageReportAsync(tenant, assessment, [1, 2, 3], CancellationToken.None);
                var published = await store.PublishReportAsync(tenant, assessment, staged, CancellationToken.None);
                publishedKeys.Add(published);
                File.SetLastWriteTimeUtc(Path.Combine(root, published.Replace('/', Path.DirectorySeparatorChar)), DateTime.UtcNow.AddHours(-3));
            }

            var t1 = Task.Run(() => store.ReconcilePublishedReportsAsync(DateTimeOffset.UtcNow.AddHours(-2), _ => Task.FromResult(false), CancellationToken.None));
            var t2 = Task.Run(() => store.ReconcilePublishedReportsAsync(DateTimeOffset.UtcNow.AddHours(-2), _ => Task.FromResult(false), CancellationToken.None));
            var results = await Task.WhenAll(t1, t2);

            Assert.True(results.Sum() >= 5);
            for (var i = 0; i < assessments.Count; i++)
            {
                Assert.Null(await store.GetPublishedReportAsync(tenant, assessments[i], publishedKeys[i], CancellationToken.None));
            }
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Missing_artifact_directories_do_not_throw()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-missing-{Guid.NewGuid():N}");
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Artifacts:Root"] = root }).Build();
        var store = new FileSystemAssessmentArtifactStore(configuration);

        var stagedCleaned = await store.CleanupStagedReportsAsync(DateTimeOffset.UtcNow.AddHours(-1), CancellationToken.None);
        var publishedCleaned = await store.ReconcilePublishedReportsAsync(DateTimeOffset.UtcNow.AddHours(-1), _ => Task.FromResult(false), CancellationToken.None);

        Assert.Equal(0, stagedCleaned);
        Assert.Equal(0, publishedCleaned);
    }

    [Fact]
    public async Task AssessmentArtifactCleanupService_runs_cycle_with_scoped_db_and_reconciles_unreferenced_reports()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-artifacts-{Guid.NewGuid():N}");
        var dbName = Guid.NewGuid().ToString();
        var services = new ServiceCollection();
        services.AddDbContext<AppDbContext>(opt => opt.UseInMemoryDatabase(dbName));
        services.AddScoped<IAppDbContext>(sp => sp.GetRequiredService<AppDbContext>());
        var sp = services.BuildServiceProvider();

        var tenant = Guid.NewGuid();
        var assessmentReferenced = Guid.NewGuid();
        var assessmentUnreferenced = Guid.NewGuid();
        try
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Artifacts:Root"] = root }).Build();
            var store = new FileSystemAssessmentArtifactStore(configuration);

            var staged1 = await store.StageReportAsync(tenant, assessmentReferenced, [1, 2, 3], CancellationToken.None);
            var publishedReferenced = await store.PublishReportAsync(tenant, assessmentReferenced, staged1, CancellationToken.None);

            var staged2 = await store.StageReportAsync(tenant, assessmentUnreferenced, [4, 5, 6], CancellationToken.None);
            var publishedUnreferenced = await store.PublishReportAsync(tenant, assessmentUnreferenced, staged2, CancellationToken.None);

            File.SetLastWriteTimeUtc(Path.Combine(root, publishedReferenced.Replace('/', Path.DirectorySeparatorChar)), DateTime.UtcNow.AddHours(-3));
            File.SetLastWriteTimeUtc(Path.Combine(root, publishedUnreferenced.Replace('/', Path.DirectorySeparatorChar)), DateTime.UtcNow.AddHours(-3));

            using (var scope = sp.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var targetScope = new TargetScope(tenant, "test scope", Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
                var job = new AgentJob(tenant, targetScope.Id, Guid.NewGuid(), "web-assessment-passive");
                var assessment = new WebAssessment(tenant, job.Id, targetScope.Id, "http://127.0.0.1/", "web-assessment-passive", WebHostingMode.Public);
                assessment.Start();
                assessment.Complete(publishedReferenced, 1);
                db.AddRange(targetScope, job, assessment);
                await db.SaveChangesAsync();
            }

            var cleanupService = new AssessmentArtifactCleanupService(
                store,
                sp.GetRequiredService<IServiceScopeFactory>(),
                NullLogger<AssessmentArtifactCleanupService>.Instance);

            var cleanedTotal = await cleanupService.RunCleanupCycleAsync(
                CancellationToken.None,
                stagedGrace: TimeSpan.FromHours(1),
                publishedGrace: TimeSpan.FromHours(1));

            Assert.Equal(1, cleanedTotal);
            Assert.Equal(new byte[] { 1, 2, 3 }, await store.GetPublishedReportAsync(tenant, assessmentReferenced, publishedReferenced, CancellationToken.None));
            Assert.Null(await store.GetPublishedReportAsync(tenant, assessmentUnreferenced, publishedUnreferenced, CancellationToken.None));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
