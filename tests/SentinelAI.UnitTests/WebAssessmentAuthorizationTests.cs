using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Agent.Vulnerability;
using SentinelAI.Application;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;
using SentinelAI.Security.Policy;

namespace SentinelAI.UnitTests;

public sealed class WebAssessmentAuthorizationTests
{
    [Fact]
    public async Task Password_form_transport_check_is_read_only_and_never_persists_the_password_value()
    {
        const string markerPassword = "sentinel-test-password-never-store";
        const string html = "<html><body><form method='GET'><input type='password' name='password' value='" + markerPassword + "'></form></body></html>";
        await using var fixture = await AssessmentFixture.CreateAsync(html);
        var engine = fixture.CreateEngine(new ImmediateReportGenerator());

        var result = await fixture.ExecuteAsync(engine);

        Assert.NotNull(result.ReportStorageKey);
        Assert.Equal(1, fixture.Server.RequestCount);

        var check = await fixture.Db.WebAssessmentChecks.AsNoTracking()
            .SingleAsync(x => x.TenantId == fixture.Tenant.Id && x.AssessmentId == fixture.Assessment.Id &&
                x.CheckId == "auth.password-form-transport");
        Assert.Equal(WebCheckStatus.FindingDetected, check.Status);
        Assert.Contains("Field values and names were not collected", check.Reason);

        var finding = await fixture.Db.Findings.AsNoTracking()
            .SingleAsync(x => x.TenantId == fixture.Tenant.Id && x.AssessmentId == fixture.Assessment.Id &&
                x.Title == "Password form transport requires review");
        var evidence = await fixture.Db.Evidence.AsNoTracking().SingleAsync(x => x.TenantId == fixture.Tenant.Id && x.FindingId == finding.Id);
        Assert.Contains("method=GET", evidence.RedactedContent);
        Assert.DoesNotContain(markerPassword, finding.Description);
        Assert.DoesNotContain(markerPassword, evidence.RedactedContent);
        Assert.DoesNotContain(markerPassword, evidence.Summary);
    }

    [Fact]
    public async Task Authorization_revoked_before_report_generation_never_starts_the_report()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var revoked = 0;

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() => engine.ExecuteAsync(
            fixture.Assessment, fixture.Job, fixture.Scope, fixture.Worker.Identity, fixture.Worker.Capabilities, [],
            (activeDb, ct) => Task.FromResult(true), CancellationToken.None,
            (activeDb, ct) => Task.FromResult<WorkerExecutionContext?>(Interlocked.Exchange(ref revoked, 1) == 0 ? fixture.WorkerContext : null)));

        Assert.False(report.Started.Task.IsCompleted);
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        Assert.Contains(await fixture.Db.AuditEvents.ToListAsync(), audit => audit.Action == "web-assessment.authorization-revoked");
    }

    [Fact]
    public async Task Capability_revocation_during_report_generation_cancels_without_publication()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = engine.ExecuteAsync(
            fixture.Assessment, fixture.Job, fixture.Scope, fixture.Worker.Identity, fixture.Worker.Capabilities, [],
            (activeDb, ct) => Task.FromResult(true), CancellationToken.None,
            (activeDb, ct) => Task.FromResult<WorkerExecutionContext?>(fixture.WorkerContext));

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.MutateWorkerAsync(w => w.ProvisionByAdministrator("test", ["passive-mock"], []));

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() => task);
        await report.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        await using var verifyDb = fixture.CreateContext();
        Assert.Contains(await verifyDb.AuditEvents.ToListAsync(), audit => audit.Action == "web-assessment.authorization-revoked");
    }

    [Fact]
    public async Task Authorization_revocation_keeps_parent_job_and_execution_consistent()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        fixture.Job.ReleaseLeaseForRetry("test retry");
        fixture.Execution.ResetForRetry();
        await fixture.Db.SaveChangesAsync();

        var service = new ScanExecutionService(fixture.Db, new ControlledValidator(), new ConfigurationBuilder().Build(),
            NullLogger<ScanExecutionService>.Instance, webAssessmentEngine: new RevokingEngine());
        var outcome = await service.ExecuteAsync(fixture.Job.Id, CancellationToken.None, fixture.Tenant.Id, fixture.Worker.Identity);

        Assert.Equal(ScanExecutionOutcome.Cancelled, outcome);
        Assert.Equal(ScanJobStatus.Cancelled, fixture.Job.Status);
        Assert.Equal(AgentExecutionStatus.Cancelled, fixture.Execution.Status);
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        Assert.Contains(await fixture.Db.AuditEvents.ToListAsync(), audit => audit.Action == "scan.authorization-revoked");
    }

    [Theory]
    [InlineData("allow-subdomains")]
    [InlineData("target")]
    [InlineData("remove-exclusion")]
    [InlineData("add-exclusion")]
    [InlineData("remove-profile")]
    [InlineData("verification-expiry")]
    [InlineData("max-total-requests")]
    [InlineData("requests-per-minute")]
    [InlineData("max-pages")]
    [InlineData("crawl-depth")]
    [InlineData("response-bytes")]
    [InlineData("execution-seconds")]
    [InlineData("private-worker")]
    [InlineData("private-ranges")]
    public async Task Scope_mutation_during_report_generation_cancels_without_publication(string mutation)
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        if (mutation is "private-worker" or "private-ranges")
            await fixture.ConfigurePrivateAssessmentAsync();

        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));

        await fixture.MutateScopeAsync(scope =>
        {
            switch (mutation)
            {
                case "allow-subdomains":
                    scope.Configure(scope.Targets, scope.Exclusions, scope.ApprovedOperationProfiles,
                        scope.RequestsPerMinute, scope.MaxExecutionSeconds, scope.AuthorizationEvidence, false,
                        allowSubdomains: true, scope.MaxTotalRequests, scope.MaxConcurrentRequests,
                        scope.MaxPages, scope.MaxCrawlDepth, scope.MaxResponseBytes);
                    break;
                case "target":
                    scope.Configure([new TargetDefinition(TargetKind.Web, "http://127.0.0.1:9999/other")], scope.Exclusions, scope.ApprovedOperationProfiles,
                        scope.RequestsPerMinute, scope.MaxExecutionSeconds, scope.AuthorizationEvidence, false,
                        scope.AllowSubdomains, scope.MaxTotalRequests, scope.MaxConcurrentRequests,
                        scope.MaxPages, scope.MaxCrawlDepth, scope.MaxResponseBytes);
                    break;
                case "remove-exclusion":
                    scope.Configure(scope.Targets, [], scope.ApprovedOperationProfiles,
                        scope.RequestsPerMinute, scope.MaxExecutionSeconds, scope.AuthorizationEvidence, false,
                        scope.AllowSubdomains, scope.MaxTotalRequests, scope.MaxConcurrentRequests,
                        scope.MaxPages, scope.MaxCrawlDepth, scope.MaxResponseBytes);
                    break;
                case "add-exclusion":
                    scope.Configure(scope.Targets, ["http://127.0.0.1/excluded"], scope.ApprovedOperationProfiles,
                        scope.RequestsPerMinute, scope.MaxExecutionSeconds, scope.AuthorizationEvidence, false,
                        scope.AllowSubdomains, scope.MaxTotalRequests, scope.MaxConcurrentRequests,
                        scope.MaxPages, scope.MaxCrawlDepth, scope.MaxResponseBytes);
                    break;
                case "remove-profile":
                    scope.Configure(scope.Targets, scope.Exclusions, ["other-profile"],
                        scope.RequestsPerMinute, scope.MaxExecutionSeconds, scope.AuthorizationEvidence, false,
                        scope.AllowSubdomains, scope.MaxTotalRequests, scope.MaxConcurrentRequests,
                        scope.MaxPages, scope.MaxCrawlDepth, scope.MaxResponseBytes);
                    break;
                case "verification-expiry":
                    scope.ConfigureVerifications([new PublicTargetVerification(fixture.Assessment.TargetUrl, "ticket", "verifier", "manual", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(-1))]);
                    break;
                case "max-total-requests":
                    scope.Configure(scope.Targets, scope.Exclusions, scope.ApprovedOperationProfiles,
                        scope.RequestsPerMinute, scope.MaxExecutionSeconds, scope.AuthorizationEvidence, false,
                        scope.AllowSubdomains, scope.MaxTotalRequests - 1, scope.MaxConcurrentRequests,
                        scope.MaxPages, scope.MaxCrawlDepth, scope.MaxResponseBytes);
                    break;
                case "requests-per-minute":
                    scope.Configure(scope.Targets, scope.Exclusions, scope.ApprovedOperationProfiles,
                        scope.RequestsPerMinute - 1, scope.MaxExecutionSeconds, scope.AuthorizationEvidence, false,
                        scope.AllowSubdomains, scope.MaxTotalRequests, scope.MaxConcurrentRequests,
                        scope.MaxPages, scope.MaxCrawlDepth, scope.MaxResponseBytes);
                    break;
                case "max-pages":
                    scope.Configure(scope.Targets, scope.Exclusions, scope.ApprovedOperationProfiles,
                        scope.RequestsPerMinute, scope.MaxExecutionSeconds, scope.AuthorizationEvidence, false,
                        scope.AllowSubdomains, scope.MaxTotalRequests, scope.MaxConcurrentRequests,
                        scope.MaxPages - 1, scope.MaxCrawlDepth, scope.MaxResponseBytes);
                    break;
                case "crawl-depth":
                    scope.Configure(scope.Targets, scope.Exclusions, scope.ApprovedOperationProfiles,
                        scope.RequestsPerMinute, scope.MaxExecutionSeconds, scope.AuthorizationEvidence, false,
                        scope.AllowSubdomains, scope.MaxTotalRequests, scope.MaxConcurrentRequests,
                        scope.MaxPages, scope.MaxCrawlDepth + 1, scope.MaxResponseBytes);
                    break;
                case "response-bytes":
                    scope.Configure(scope.Targets, scope.Exclusions, scope.ApprovedOperationProfiles,
                        scope.RequestsPerMinute, scope.MaxExecutionSeconds, scope.AuthorizationEvidence, false,
                        scope.AllowSubdomains, scope.MaxTotalRequests, scope.MaxConcurrentRequests,
                        scope.MaxPages, scope.MaxCrawlDepth, scope.MaxResponseBytes - 1024);
                    break;
                case "execution-seconds":
                    scope.Configure(scope.Targets, scope.Exclusions, scope.ApprovedOperationProfiles,
                        scope.RequestsPerMinute, scope.MaxExecutionSeconds - 10, scope.AuthorizationEvidence, false,
                        scope.AllowSubdomains, scope.MaxTotalRequests, scope.MaxConcurrentRequests,
                        scope.MaxPages, scope.MaxCrawlDepth, scope.MaxResponseBytes);
                    break;
                case "private-worker":
                    scope.ConfigureWebHosting(WebHostingMode.Private, "other-worker", ["10.0.0.0/8"]);
                    break;
                case "private-ranges":
                    scope.ConfigureWebHosting(WebHostingMode.Private, fixture.Worker.Identity, ["10.1.0.0/16"]);
                    break;
            }
        });

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() => task);
        await report.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        Assert.Empty(fixture.ArtifactStore.PublishedKeys);
    }

    [Fact]
    public async Task Worker_unhealthy_during_report_generation_cancels_without_publication()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.MutateWorkerAsync(w => w.MarkUnhealthy());

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() => task);
        await report.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        await using var verifyDb = fixture.CreateContext();
        Assert.Contains(await verifyDb.AuditEvents.ToListAsync(), audit => audit.Action == "web-assessment.authorization-revoked");
    }

    [Fact]
    public async Task Worker_assignment_change_during_report_generation_requeues_for_retry()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.MutateJobAsync(job =>
        {
            job.ReleaseLeaseForRetry("lease takeover");
            Assert.True(job.TryAcquireLease("worker-b", DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1)));
        });

        await Assert.ThrowsAsync<WebAssessmentLeaseLostException>(() => task);
        await report.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WebAssessmentStatus.Queued, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        await using var verifyDb = fixture.CreateContext();
        Assert.DoesNotContain(await verifyDb.AuditEvents.ToListAsync(), audit => audit.Action == "web-assessment.authorization-revoked");
    }

    [Fact]
    public async Task Report_generation_failure_sets_status_failed_and_discards_artifacts()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new ThrowingReportGenerator();
        var engine = fixture.CreateEngine(report);

        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.ExecuteAsync(engine));
        Assert.Equal(WebAssessmentStatus.Failed, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        Assert.Empty(fixture.ArtifactStore.PublishedKeys);
    }

    [Fact]
    public async Task Publication_failure_sets_status_failed_and_discards_staged_artifact()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        fixture.ArtifactStore.FailPublication = true;
        var report = new CompletingReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        report.Complete();

        await Assert.ThrowsAsync<IOException>(() => task);
        Assert.Equal(WebAssessmentStatus.Failed, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        Assert.Contains(fixture.ArtifactStore.DiscardedKeys, key => key.Contains("/.staging/"));
        Assert.Empty(fixture.ArtifactStore.PublishedKeys);
    }

    [Fact]
    public async Task Scope_mutation_before_parent_transaction_cancels_and_discards_published_report()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        fixture.Job.ReleaseLeaseForRetry("test retry");
        fixture.Execution.ResetForRetry();
        await fixture.Db.SaveChangesAsync();

        var engine = new CompletingEngine(fixture.ArtifactStore);
        var service = new ScanExecutionService(fixture.Db, new ControlledValidator(), new ConfigurationBuilder().Build(),
            NullLogger<ScanExecutionService>.Instance, webAssessmentEngine: engine, artifactStore: fixture.ArtifactStore);

        // Mutate scope right after engine runs but before ScanExecutionService's completion transaction
        engine.OnAfterExecute = async () =>
        {
            var scope = await fixture.Db.TargetScopes.SingleAsync(x => x.Id == fixture.Scope.Id);
            scope.Configure(scope.Targets, scope.Exclusions, scope.ApprovedOperationProfiles,
                scope.RequestsPerMinute, scope.MaxExecutionSeconds, scope.AuthorizationEvidence, false,
                scope.AllowSubdomains, scope.MaxTotalRequests - 1, scope.MaxConcurrentRequests,
                scope.MaxPages, scope.MaxCrawlDepth, scope.MaxResponseBytes);
            await fixture.Db.SaveChangesAsync();
        };

        var outcome = await service.ExecuteAsync(fixture.Job.Id, CancellationToken.None, fixture.Tenant.Id, fixture.Worker.Identity);

        Assert.Equal(ScanExecutionOutcome.Cancelled, outcome);
        Assert.Equal(ScanJobStatus.Cancelled, fixture.Job.Status);
        Assert.Equal(AgentExecutionStatus.Cancelled, fixture.Execution.Status);
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
        Assert.Contains(await fixture.Db.AuditEvents.ToListAsync(), audit => audit.Action == "scan.authorization-revoked");
        Assert.Contains(fixture.ArtifactStore.DiscardedKeys, key => key.Contains("/reports/"));
    }

    [Fact]
    public async Task Lease_loss_before_parent_transaction_does_not_revoke_authorization()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        fixture.Job.ReleaseLeaseForRetry("test retry");
        fixture.Execution.ResetForRetry();
        await fixture.Db.SaveChangesAsync();

        var engine = new CompletingEngine(fixture.ArtifactStore);
        var service = new ScanExecutionService(fixture.Db, new ControlledValidator(), new ConfigurationBuilder().Build(),
            NullLogger<ScanExecutionService>.Instance, webAssessmentEngine: engine, artifactStore: fixture.ArtifactStore);

        // Take over lease right after engine completes
        engine.OnAfterExecute = async () =>
        {
            var job = await fixture.Db.AgentJobs.SingleAsync(x => x.Id == fixture.Job.Id);
            job.ReleaseLeaseForRetry("lease takeover");
            job.TryAcquireLease("worker-b", DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1));
            await fixture.Db.SaveChangesAsync();
        };

        var outcome = await service.ExecuteAsync(fixture.Job.Id, CancellationToken.None, fixture.Tenant.Id, fixture.Worker.Identity);

        Assert.Equal(ScanExecutionOutcome.ClaimedByAnotherWorker, outcome);
        Assert.DoesNotContain(await fixture.Db.AuditEvents.ToListAsync(), audit => audit.Action == "scan.authorization-revoked");
        Assert.Contains(fixture.ArtifactStore.DiscardedKeys, key => key.Contains("/reports/"));
    }

    [Fact]
    public async Task Lease_loss_during_report_generation_is_distinct_and_requeues_the_assessment()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.MutateJobAsync(job => job.ReleaseLeaseForRetry("lease takeover"));

        await Assert.ThrowsAsync<WebAssessmentLeaseLostException>(() => task);
        await report.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WebAssessmentStatus.Queued, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        await using var verifyDb = fixture.CreateContext();
        Assert.DoesNotContain(await verifyDb.AuditEvents.ToListAsync(), audit => audit.Action == "web-assessment.authorization-revoked");
    }

    [Fact]
    public async Task Private_capability_removal_during_report_generation_prevents_publication()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        await fixture.ConfigurePrivateAssessmentAsync();
        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.MutateWorkerAsync(w => w.ProvisionByAdministrator("test", [WebAssessmentCapabilities.WebAssessment], []));

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() => task);
        await report.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
    }

    [Fact]
    public async Task Scope_expiry_during_report_generation_cancels_without_publication()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.MutateScopeAsync(s => s.ExpireAuthorization());

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() => task);
        await report.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
    }

    [Fact]
    public async Task Revocation_at_the_completion_boundary_blocks_publication()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new CompletingReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.MutateWorkerAsync(w => w.ProvisionByAdministrator("test", ["passive-mock"], []));
        report.Complete();

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() => task);
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
    }

    [Fact]
    public async Task Authorization_monitoring_uses_independent_context_instances_and_disposes_each()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var trackingFactory = new TrackingDbContextFactory(fixture.Options);
        var report = new CompletingReportGenerator();
        var engine = fixture.CreateEngine(report, trackingFactory);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var waited = 0;
        while (trackingFactory.CreationCount < 2 && waited++ < 50)
            await Task.Delay(25);

        report.Complete();
        var result = await task;

        Assert.NotNull(result.ReportStorageKey);
        Assert.True(trackingFactory.CreationCount >= 2);
        Assert.All(trackingFactory.CreatedContexts, ctx => Assert.NotSame(fixture.Db, ctx.Inner));
        Assert.All(trackingFactory.CreatedContexts, ctx => Assert.True(ctx.IsDisposed));

        var finalCount = trackingFactory.CreationCount;
        await Task.Delay(100);
        Assert.Equal(finalCount, trackingFactory.CreationCount);
    }

    [Fact]
    public async Task Concurrent_report_queries_and_monitor_queries_never_produce_concurrency_exceptions()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var trackingFactory = new TrackingDbContextFactory(fixture.Options);
        var report = new ConcurrentQueryingReportGenerator(fixture.Db);
        var engine = fixture.CreateEngine(report, trackingFactory);

        var result = await fixture.ExecuteAsync(engine);

        Assert.NotNull(result.ReportStorageKey);
        Assert.False(string.IsNullOrEmpty(result.ReportStorageKey));
        Assert.True(trackingFactory.CreationCount > 0);
    }

    [Fact]
    public async Task Lease_loss_is_detected_while_report_generation_is_blocked()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.MutateJobAsync(j => j.ReleaseLeaseForRetry("lease revoked"));

        await Assert.ThrowsAsync<WebAssessmentLeaseLostException>(() => task);
        await report.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WebAssessmentStatus.Queued, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
    }

    [Fact]
    public async Task Parent_cancellation_propagates_cleanly_as_OperationCanceledException()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        using var cts = new CancellationTokenSource();
        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = engine.ExecuteAsync(fixture.Assessment, fixture.Job, fixture.Scope, fixture.Worker.Identity, fixture.Worker.Capabilities, fixture.Worker.ApprovedPrivateNetworkRanges, (activeDb, ct) => Task.FromResult(true), cts.Token, (activeDb, ct) => Task.FromResult<WorkerExecutionContext?>(fixture.WorkerContext));

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        Assert.Empty(fixture.ArtifactStore.PublishedKeys);
    }

    [Fact]
    public async Task Simultaneous_lease_loss_at_report_completion_prevents_publication()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new CompletingReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.MutateJobAsync(j => j.ReleaseLeaseForRetry("lease stolen"));
        report.Complete();

        await Assert.ThrowsAsync<WebAssessmentLeaseLostException>(() => task);
        Assert.Equal(WebAssessmentStatus.Queued, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        Assert.Empty(fixture.ArtifactStore.PublishedKeys);
    }

    [Fact]
    public async Task Worker_revocation_is_detected_during_report_generation()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.MutateWorkerAsync(w => w.MarkUnhealthy());

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() => task);
        await report.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        Assert.Empty(fixture.ArtifactStore.PublishedKeys);
    }

    [Fact]
    public async Task Scope_mutation_is_detected_during_report_generation()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.MutateScopeAsync(s => s.Configure([new TargetDefinition(TargetKind.Web, $"http://127.0.0.1:{fixture.Server.Port}/mutated")], [], ["web-assessment-passive"], 100, 120, "controlled-test", false));

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() => task);
        await report.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        Assert.Empty(fixture.ArtifactStore.PublishedKeys);
    }

    [Fact]
    public async Task Scope_expiry_is_detected_during_report_generation()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.MutateScopeAsync(s => s.ExpireAuthorization());

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() => task);
        await report.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        Assert.Empty(fixture.ArtifactStore.PublishedKeys);
    }

    [Fact]
    public async Task Private_worker_capability_removal_is_detected_during_report_generation()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        await fixture.ConfigurePrivateAssessmentAsync();

        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.MutateWorkerAsync(w => w.ProvisionByAdministrator("test", [WebAssessmentCapabilities.WebAssessment], []));

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() => task);
        await report.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        Assert.Empty(fixture.ArtifactStore.PublishedKeys);
    }

    [Fact]
    public async Task Job_cancellation_during_report_generation_is_detected_as_lease_lost()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.MutateJobAsync(j => j.Cancel());

        await Assert.ThrowsAsync<WebAssessmentLeaseLostException>(() => task);
        await report.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WebAssessmentStatus.Queued, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        Assert.Empty(fixture.ArtifactStore.PublishedKeys);
    }

    [Fact]
    public async Task Monitor_db_failure_during_report_generation_aborts_report_and_propagates()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new ControlledReportGenerator();
        var failingFactory = new FailingDbContextFactory();
        var engine = fixture.CreateEngine(report, failingFactory);
        var task = fixture.ExecuteAsync(engine);

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.ThrowsAsync<InvalidOperationException>(() => task);
        await report.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WebAssessmentStatus.Failed, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        Assert.Empty(fixture.ArtifactStore.PublishedKeys);
    }

    [Fact]
    public async Task Report_generation_failure_shuts_down_monitor_cleanly()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var trackingFactory = new TrackingDbContextFactory(fixture.Options);
        var throwingReport = new ThrowingReportGenerator();
        var engine = fixture.CreateEngine(throwingReport, trackingFactory);

        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.ExecuteAsync(engine));
        var count = trackingFactory.CreationCount;
        await Task.Delay(100);
        Assert.Equal(count, trackingFactory.CreationCount);
        Assert.All(trackingFactory.CreatedContexts, ctx => Assert.True(ctx.IsDisposed));
    }

    [Fact]
    public async Task WebAssessmentEngine_requires_non_null_independent_context_factory()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new ControlledReportGenerator();
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new WebAssessmentEngine(
                fixture.Db,
                new ControlledValidator(),
                fixture.ArtifactStore,
                new ControlledScreenshotService(),
                report,
                new ConfigurationBuilder().Build(),
                dbFactory: null!));

        Assert.Equal("dbFactory", ex.ParamName);
        Assert.Contains("independent database context factory", ex.Message);
    }

    [Fact]
    public async Task Synchronous_report_setup_failure_yields_precedence_to_security_exception()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var trackingFactory = new TrackingDbContextFactory(fixture.Options);

        var throwingReport = new SynchronousThrowingReportGenerator(() =>
        {
            using var syncDb = fixture.CreateContext();
            var worker = syncDb.Workers.Single(x => x.TenantId == fixture.Job.TenantId && x.Identity == fixture.Worker.Identity);
            worker.ProvisionByAdministrator("test", ["passive-mock"], []);
            syncDb.SaveChanges();
        });
        var engine = fixture.CreateEngine(throwingReport, trackingFactory);

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() => fixture.ExecuteAsync(engine));
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
    }

    private sealed class AssessmentFixture : IAsyncDisposable
    {
        private AssessmentFixture(DbContextOptions<AppDbContext> options, AppDbContext db, LoopbackHttpServer server, Tenant tenant, User user, TargetScope scope, WorkerRegistration worker, AgentJob job, AgentExecution execution, WebAssessment assessment)
        {
            Options = options;
            Db = db;
            DbFactory = new DefaultAppDbContextFactory(() => new AppDbContext(options));
            Server = server;
            Tenant = tenant;
            User = user;
            Scope = scope;
            Worker = worker;
            Job = job;
            Execution = execution;
            Assessment = assessment;
            WorkerContext = new(worker.Identity, worker.Capabilities, worker.ApprovedPrivateNetworkRanges);
        }

        public DbContextOptions<AppDbContext> Options { get; }
        public IAppDbContextFactory DbFactory { get; }
        public AppDbContext Db { get; }
        public LoopbackHttpServer Server { get; }
        public Tenant Tenant { get; }
        public User User { get; }
        public TargetScope Scope { get; }
        public WorkerRegistration Worker { get; }
        public AgentJob Job { get; }
        public AgentExecution Execution { get; }
        public WebAssessment Assessment { get; }
        public WorkerExecutionContext WorkerContext { get; private set; }

        public static async Task<AssessmentFixture> CreateAsync(string? responseBody = null)
        {
            var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
            var db = new AppDbContext(options);
            var server = new LoopbackHttpServer(responseBody);
            var tenant = new Tenant("web authorization tenant");
            var user = new User(tenant.Id, "web-authorization-user", "Test", UserRole.SecurityAnalyst);
            var scope = new TargetScope(tenant.Id, "web authorization scope", user.Id, DateTimeOffset.UtcNow.AddMinutes(5));
            var target = $"http://127.0.0.1:{server.Port}/";
            scope.Configure([new TargetDefinition(TargetKind.Web, target)], ["http://127.0.0.1/initial-exclusion"], ["web-assessment-passive"], 100, 120, "controlled-test", false);
            scope.ConfigureVerifications([new PublicTargetVerification(target, "ticket", "verifier", "manual", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1))]);
            var worker = new WorkerRegistration(tenant.Id, "worker-a", "test", [WebAssessmentCapabilities.WebAssessment]);
            worker.Heartbeat(0, 1);
            var job = new AgentJob(tenant.Id, scope.Id, user.Id, "web-assessment-passive");
            Assert.True(job.TryAcquireLease(worker.Identity, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1)));
            var execution = new AgentExecution(job.Id, "AuthorizedWebAssessmentAgent");
            var assessment = new WebAssessment(tenant.Id, job.Id, scope.Id, target, "web-assessment-passive", WebHostingMode.Public);
            db.AddRange(tenant, user, scope, worker, job, execution, assessment);
            await db.SaveChangesAsync();
            return new AssessmentFixture(options, db, server, tenant, user, scope, worker, job, execution, assessment);
        }

        public MemoryArtifactStore ArtifactStore { get; } = new();

        public WebAssessmentEngine CreateEngine(IHtmlReportGenerator report, IAppDbContextFactory? dbFactory = null)
            => new(Db, new ControlledValidator(), ArtifactStore, new ControlledScreenshotService(), report,
                new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["WebAssessment:AuthorizationRefreshIntervalMs"] = "25" }).Build(),
                dbFactory ?? DbFactory);

        public Task<WebAssessmentExecutionResult> ExecuteAsync(WebAssessmentEngine engine)
            => engine.ExecuteAsync(Assessment, Job, Scope, Worker.Identity, Worker.Capabilities, Worker.ApprovedPrivateNetworkRanges,
                async (activeDb, ct) => await activeDb.AgentJobs.AsNoTracking().AnyAsync(x => x.Id == Job.Id && x.Status == ScanJobStatus.Running && x.LeaseOwnerWorkerId == Worker.Identity && x.LeaseExpiresAt > DateTimeOffset.UtcNow, ct),
                CancellationToken.None,
                async (activeDb, ct) =>
                {
                    var worker = await activeDb.Workers.AsNoTracking().SingleOrDefaultAsync(x => x.TenantId == Job.TenantId && x.Identity == Worker.Identity, ct);
                    if (worker is null || !worker.IsHealthyForAdmission(DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5)) ||
                        !worker.Capabilities.Contains(WebAssessmentCapabilities.WebAssessment, StringComparer.OrdinalIgnoreCase)) return null;
                    if (Scope.WebHostingMode == WebHostingMode.Private &&
                        (!string.Equals(Scope.PrivateWorkerIdentity, Worker.Identity, StringComparison.Ordinal) ||
                         !worker.Capabilities.Contains(WebAssessmentCapabilities.PrivateWebAssessment, StringComparer.OrdinalIgnoreCase) ||
                         !worker.PrivateAssessmentApproved || worker.ApprovedPrivateNetworkRanges.Count == 0)) return null;
                    return new WorkerExecutionContext(worker.Identity, worker.Capabilities.ToArray(), worker.ApprovedPrivateNetworkRanges.ToArray());
                });

        public void ConfigurePrivateAssessment()
        {
            Scope.ConfigureWebHosting(WebHostingMode.Private, Worker.Identity, ["10.0.0.0/8"]);
            Worker.ProvisionByAdministrator("test", [WebAssessmentCapabilities.WebAssessment, WebAssessmentCapabilities.PrivateWebAssessment], ["10.0.0.0/8"]);
            WorkerContext = new WorkerExecutionContext(Worker.Identity, Worker.Capabilities.ToArray(), Worker.ApprovedPrivateNetworkRanges.ToArray());
        }

        public AppDbContext CreateContext() => new(Options);

        public async Task ConfigurePrivateAssessmentAsync()
        {
            Scope.ConfigureWebHosting(WebHostingMode.Private, Worker.Identity, ["10.0.0.0/8"]);
            Worker.ProvisionByAdministrator("test", [WebAssessmentCapabilities.WebAssessment, WebAssessmentCapabilities.PrivateWebAssessment], ["10.0.0.0/8"]);
            WorkerContext = new WorkerExecutionContext(Worker.Identity, Worker.Capabilities.ToArray(), Worker.ApprovedPrivateNetworkRanges.ToArray());
            await Db.SaveChangesAsync();
        }

        public async Task MutateScopeAsync(Action<TargetScope> mutate)
        {
            await using var mutationDb = CreateContext();
            var scope = await mutationDb.TargetScopes.SingleAsync(x => x.Id == Scope.Id);
            mutate(scope);
            await mutationDb.SaveChangesAsync();
        }

        public async Task MutateWorkerAsync(Action<WorkerRegistration> mutate)
        {
            await using var mutationDb = CreateContext();
            var worker = await mutationDb.Workers.SingleAsync(x => x.TenantId == Job.TenantId && x.Identity == Worker.Identity);
            mutate(worker);
            await mutationDb.SaveChangesAsync();
        }

        public async Task MutateJobAsync(Action<AgentJob> mutate)
        {
            await using var mutationDb = CreateContext();
            var job = await mutationDb.AgentJobs.SingleAsync(x => x.Id == Job.Id);
            mutate(job);
            await mutationDb.SaveChangesAsync();
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await Server.DisposeAsync();
        }
    }

    private sealed class ControlledValidator : ITargetScopeValidator
    {
        public ScopeValidationResult ValidateDefinition(TargetScope scope, Guid tenantId, DateTimeOffset now) => ScopeValidationResult.Valid();
        public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, string target, string operationProfile, CancellationToken cancellationToken = default)
            => ValidateExecutionAsync(scope, tenantId, TargetKind.Network, target, operationProfile, null, cancellationToken);
        public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, TargetKind kind, string target, string operationProfile, CancellationToken cancellationToken = default)
            => ValidateExecutionAsync(scope, tenantId, kind, target, operationProfile, null, cancellationToken);
        public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, TargetKind kind, string target, string operationProfile, WorkerExecutionContext? worker, CancellationToken cancellationToken = default)
        {
            var uri = new Uri(target, UriKind.Absolute);
            return ValueTask.FromResult(ScopeValidationResult.Valid(new ValidatedExecutionTarget(uri.Host, [IPAddress.Loopback], DateTimeOffset.UtcNow, scope.Id, tenantId, scope.ExpiresAt, operationProfile)));
        }
        public ValueTask<ScopeValidationResult> ValidateRedirectAsync(TargetScope scope, Guid tenantId, Uri redirect, string operationProfile, CancellationToken cancellationToken = default)
            => ValidateExecutionAsync(scope, tenantId, TargetKind.Web, redirect.ToString(), operationProfile, cancellationToken);
    }

    private sealed class ControlledScreenshotService : IScreenshotCaptureService
    {
        public Task<byte[]> CaptureAsync(BrowserAssessmentContext context, CancellationToken cancellationToken) => Task.FromResult<byte[]>([137, 80, 78, 71]);
    }

    private sealed class RevokingEngine : IWebAssessmentEngine
    {
        public Task<WebAssessmentExecutionResult> ExecuteAsync(WebAssessment assessment, AgentJob job, TargetScope scope, string workerIdentity,
            IReadOnlyCollection<string> workerCapabilities, IReadOnlyCollection<string>? approvedPrivateNetworkRanges, Func<IAppDbContext, CancellationToken, Task<bool>> leaseCheck,
            CancellationToken cancellationToken, Func<IAppDbContext, CancellationToken, Task<WorkerExecutionContext?>>? refreshAuthorization = null)
            => throw new WebAssessmentAuthorizationRevokedException();
    }

    private sealed class ThrowingReportGenerator : IHtmlReportGenerator
    {
        public Task<string> GenerateAsync(Guid tenantId, WebAssessment assessment, TargetScope scope, CancellationToken cancellationToken, bool includeAdvisoryAiSummaries = false)
            => throw new InvalidOperationException("Disk or rendering failure.");
    }

    private sealed class SynchronousThrowingReportGenerator(Action onGenerate) : IHtmlReportGenerator
    {
        public Task<string> GenerateAsync(Guid tenantId, WebAssessment assessment, TargetScope scope, CancellationToken cancellationToken, bool includeAdvisoryAiSummaries = false)
        {
            onGenerate();
            throw new InvalidOperationException("Disk or rendering failure during setup.");
        }
    }

    private sealed class CompletingEngine(IAssessmentArtifactStore artifacts) : IWebAssessmentEngine
    {
        public Func<Task>? OnAfterExecute { get; set; }
        public async Task<WebAssessmentExecutionResult> ExecuteAsync(WebAssessment assessment, AgentJob job, TargetScope scope, string workerIdentity,
            IReadOnlyCollection<string> workerCapabilities, IReadOnlyCollection<string>? approvedPrivateNetworkRanges, Func<IAppDbContext, CancellationToken, Task<bool>> leaseCheck,
            CancellationToken cancellationToken, Func<IAppDbContext, CancellationToken, Task<WorkerExecutionContext?>>? refreshAuthorization = null)
        {
            var staged = await artifacts.StageReportAsync(job.TenantId, assessment.Id, [1, 2, 3], cancellationToken);
            var published = await artifacts.PublishReportAsync(job.TenantId, assessment.Id, staged, cancellationToken);
            if (OnAfterExecute is not null) await OnAfterExecute();
            return new WebAssessmentExecutionResult(published, 1);
        }
    }

    private sealed class ControlledReportGenerator : IHtmlReportGenerator
    {
        public TaskCompletionSource<bool> Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> Cancelled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<string> GenerateAsync(Guid tenantId, WebAssessment assessment, TargetScope scope, CancellationToken cancellationToken, bool includeAdvisoryAiSummaries = false)
        {
            Started.TrySetResult(true);
            try { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); }
            catch (OperationCanceledException)
            {
                Cancelled.TrySetResult(true);
                throw;
            }

            return "unreachable";
        }
    }

    private sealed class CompletingReportGenerator : IHtmlReportGenerator
    {
        public TaskCompletionSource<bool> Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<bool> completed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void Complete() => completed.TrySetResult(true);
        public async Task<string> GenerateAsync(Guid tenantId, WebAssessment assessment, TargetScope scope, CancellationToken cancellationToken, bool includeAdvisoryAiSummaries = false)
        {
            Started.TrySetResult(true);
            await completed.Task.WaitAsync(cancellationToken);
            return $"{tenantId}/{assessment.Id}/.staging/report.html";
        }
    }

    private sealed class MemoryArtifactStore : IAssessmentArtifactStore
    {
        public List<string> PublishedKeys { get; } = [];
        public List<string> DiscardedKeys { get; } = [];
        public bool FailPublication { get; set; }

        public Task<string> PutAsync(Guid tenantId, Guid assessmentId, string name, byte[] content, CancellationToken cancellationToken) => Task.FromResult($"{tenantId}/{assessmentId}/{name}");
        public Task<byte[]?> GetAsync(Guid tenantId, string storageKey, CancellationToken cancellationToken) => Task.FromResult<byte[]?>([137, 80, 78, 71]);
        public Task<string> StageReportAsync(Guid tenantId, Guid assessmentId, byte[] content, CancellationToken cancellationToken) => Task.FromResult($"{tenantId}/{assessmentId}/.staging/report.html");
        public Task<string> PublishReportAsync(Guid tenantId, Guid assessmentId, string stagingKey, CancellationToken cancellationToken)
        {
            if (FailPublication) throw new IOException("Disk failure during publication.");
            var key = $"{tenantId}/{assessmentId}/reports/report.html";
            lock (PublishedKeys) PublishedKeys.Add(key);
            return Task.FromResult(key);
        }
        public Task<byte[]?> GetPublishedReportAsync(Guid tenantId, Guid assessmentId, string storageKey, CancellationToken cancellationToken) => Task.FromResult<byte[]?>(null);
        public Task DiscardReportAsync(Guid tenantId, Guid assessmentId, string storageKey, CancellationToken cancellationToken)
        {
            lock (DiscardedKeys) DiscardedKeys.Add(storageKey);
            return Task.CompletedTask;
        }
        public Task<int> CleanupStagedReportsAsync(DateTimeOffset olderThan, CancellationToken cancellationToken) => Task.FromResult(0);
        public Task<int> ReconcilePublishedReportsAsync(DateTimeOffset olderThan, Func<string, Task<bool>> isReferencedAsync, CancellationToken cancellationToken) => Task.FromResult(0);
    }

    public sealed class TrackedAppDbContext(AppDbContext inner) : IAppDbContext
    {
        public AppDbContext Inner => inner;
        public bool IsDisposed { get; private set; }
        public DbSet<Tenant> Tenants => inner.Tenants;
        public DbSet<User> Users => inner.Users;
        public DbSet<TargetScope> TargetScopes => inner.TargetScopes;
        public DbSet<ScanPolicy> ScanPolicies => inner.ScanPolicies;
        public DbSet<AgentJob> AgentJobs => inner.AgentJobs;
        public DbSet<AgentExecution> AgentExecutions => inner.AgentExecutions;
        public DbSet<Asset> Assets => inner.Assets;
        public DbSet<AssetService> AssetServices => inner.AssetServices;
        public DbSet<Finding> Findings => inner.Findings;
        public DbSet<Evidence> Evidence => inner.Evidence;
        public DbSet<ApprovalRequest> ApprovalRequests => inner.ApprovalRequests;
        public DbSet<AuditEvent> AuditEvents => inner.AuditEvents;
        public DbSet<AIAnalysis> AIAnalyses => inner.AIAnalyses;
        public DbSet<FindingAIAnalysis> FindingAIAnalyses => inner.FindingAIAnalyses;
        public DbSet<Notification> Notifications => inner.Notifications;
        public DbSet<AssessmentSchedule> AssessmentSchedules => inner.AssessmentSchedules;
        public DbSet<AssessmentScheduleRun> AssessmentScheduleRuns => inner.AssessmentScheduleRuns;
        public DbSet<AssessmentDriftEvent> AssessmentDriftEvents => inner.AssessmentDriftEvents;
        public DbSet<WorkerRegistration> Workers => inner.Workers;
        public DbSet<WorkerClientCertificate> WorkerClientCertificates => inner.WorkerClientCertificates;
        public DbSet<PublicTargetAuthorization> PublicTargetAuthorizations => inner.PublicTargetAuthorizations;
        public DbSet<OutboxMessage> OutboxMessages => inner.OutboxMessages;
        public DbSet<WebAssessment> WebAssessments => inner.WebAssessments;
        public DbSet<WebAssessmentEndpoint> WebAssessmentEndpoints => inner.WebAssessmentEndpoints;
        public DbSet<AssessmentScreenshot> AssessmentScreenshots => inner.AssessmentScreenshots;
        public DbSet<WebAssessmentCheck> WebAssessmentChecks => inner.WebAssessmentChecks;
        public DbSet<VulnerabilityCatalogEntry> VulnerabilityCatalogEntries => inner.VulnerabilityCatalogEntries;
        public DbSet<VulnerabilityCvssMetric> VulnerabilityCvssMetrics => inner.VulnerabilityCvssMetrics;
        public DbSet<VulnerabilityKevEntry> VulnerabilityKevEntries => inner.VulnerabilityKevEntries;
        public DbSet<VulnerabilityEpssScore> VulnerabilityEpssScores => inner.VulnerabilityEpssScores;
        public DbSet<VulnerabilitySyncCheckpoint> VulnerabilitySyncCheckpoints => inner.VulnerabilitySyncCheckpoints;
        public DbSet<SoftwareComponent> SoftwareComponents => inner.SoftwareComponents;
        public DbSet<AssetVulnerabilityMatch> AssetVulnerabilityMatches => inner.AssetVulnerabilityMatches;
        public DbSet<VulnerabilityMatchTransition> VulnerabilityMatchTransitions => inner.VulnerabilityMatchTransitions;
        public DbSet<VulnerabilityTriageAssessment> VulnerabilityTriageAssessments => inner.VulnerabilityTriageAssessments;
        public Task PersistWebAssessmentEndpointsAsync(Guid tenantId, Guid assessmentId, IReadOnlyCollection<WebAssessmentEndpoint> endpoints, CancellationToken cancellationToken = default) => inner.PersistWebAssessmentEndpointsAsync(tenantId, assessmentId, endpoints, cancellationToken);
        public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default) => inner.SaveChangesAsync(cancellationToken);
        public Task<IAppDbTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default) => inner.BeginTransactionAsync(cancellationToken);
        public void Dispose()
        {
            IsDisposed = true;
            inner.Dispose();
        }
        public async ValueTask DisposeAsync()
        {
            IsDisposed = true;
            await inner.DisposeAsync();
        }
    }

    public sealed class FailingDbContextFactory : IAppDbContextFactory
    {
        public IAppDbContext CreateDbContext() => throw new InvalidOperationException("Simulated database connection failure.");
    }

    public sealed class TrackingDbContextFactory(DbContextOptions<AppDbContext> options) : IAppDbContextFactory
    {
        public ConcurrentBag<TrackedAppDbContext> CreatedContexts { get; } = [];
        public int CreationCount => CreatedContexts.Count;

        public IAppDbContext CreateDbContext()
        {
            var ctx = new TrackedAppDbContext(new AppDbContext(options));
            CreatedContexts.Add(ctx);
            return ctx;
        }
    }

    private sealed class ConcurrentQueryingReportGenerator(AppDbContext scopedDb) : IHtmlReportGenerator
    {
        public async Task<string> GenerateAsync(Guid tenantId, WebAssessment assessment, TargetScope scope, CancellationToken cancellationToken, bool includeAdvisoryAiSummaries = false)
        {
            for (var i = 0; i < 20; i++)
            {
                await scopedDb.Findings.AsNoTracking().ToListAsync(cancellationToken);
                await scopedDb.Evidence.AsNoTracking().ToListAsync(cancellationToken);
                await scopedDb.AgentJobs.AsNoTracking().ToListAsync(cancellationToken);
                await Task.Delay(10, cancellationToken);
            }
            return $"{tenantId}/{assessment.Id}/.staging/report.html";
        }
    }

    private sealed class ImmediateReportGenerator : IHtmlReportGenerator
    {
        public Task<string> GenerateAsync(Guid tenantId, WebAssessment assessment, TargetScope scope, CancellationToken cancellationToken, bool includeAdvisoryAiSummaries = false)
            => Task.FromResult($"{tenantId}/{assessment.Id}/.staging/report.html");
    }

    private sealed class LoopbackHttpServer : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly Task loop;
        private readonly byte[] responseBytes;
        private int requestCount;

        public LoopbackHttpServer(string? responseBody = null)
        {
            responseBytes = Encoding.UTF8.GetBytes(responseBody ?? "<html><body>ok</body></html>");
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            loop = ServeAsync();
        }

        public int Port { get; }
        public int RequestCount => Volatile.Read(ref requestCount);

        private async Task ServeAsync()
        {
            try
            {
                while (!shutdown.IsCancellationRequested)
                {
                    using var client = await listener.AcceptTcpClientAsync(shutdown.Token);
                    using var stream = client.GetStream();
                    var buffer = new byte[8192];
                    _ = await stream.ReadAsync(buffer, shutdown.Token);
                    Interlocked.Increment(ref requestCount);
                    var header = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {responseBytes.Length}\r\nConnection: close\r\n\r\n");
                    await stream.WriteAsync(header, shutdown.Token);
                    await stream.WriteAsync(responseBytes, shutdown.Token);
                }
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            catch (SocketException) when (shutdown.IsCancellationRequested) { }
            catch (ObjectDisposedException) when (shutdown.IsCancellationRequested) { }
        }
        public async ValueTask DisposeAsync()
        {
            shutdown.Cancel();
            listener.Stop();
            try { await loop; }
            catch (ObjectDisposedException) { }
            catch (SocketException) when (shutdown.IsCancellationRequested) { }
            shutdown.Dispose();
        }
    }
}
