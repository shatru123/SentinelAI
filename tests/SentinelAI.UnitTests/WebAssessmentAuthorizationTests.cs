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
    public async Task Authorization_revoked_before_report_generation_never_starts_the_report()
    {
        await using var fixture = await AssessmentFixture.CreateAsync();
        var report = new ControlledReportGenerator();
        var engine = fixture.CreateEngine(report);
        var revoked = 0;

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() => engine.ExecuteAsync(
            fixture.Assessment, fixture.Job, fixture.Scope, fixture.Worker.Identity, fixture.Worker.Capabilities, [],
            _ => Task.FromResult(true), CancellationToken.None,
            _ => Task.FromResult<WorkerExecutionContext?>(Interlocked.Exchange(ref revoked, 1) == 0 ? fixture.WorkerContext : null)));

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
            _ => Task.FromResult(true), CancellationToken.None,
            _ => Task.FromResult<WorkerExecutionContext?>(fixture.WorkerContext));

        await report.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        fixture.Worker.ProvisionByAdministrator("test", ["passive-mock"], []);
        await fixture.Db.SaveChangesAsync();

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() => task);
        await report.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WebAssessmentStatus.Cancelled, fixture.Assessment.Status);
        Assert.Null(fixture.Assessment.ReportStorageKey);
        Assert.Contains(await fixture.Db.AuditEvents.ToListAsync(), audit => audit.Action == "web-assessment.authorization-revoked");
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

    private sealed class AssessmentFixture : IAsyncDisposable
    {
        private AssessmentFixture(AppDbContext db, LoopbackHttpServer server, Tenant tenant, User user, TargetScope scope, WorkerRegistration worker, AgentJob job, AgentExecution execution, WebAssessment assessment)
        { Db = db; Server = server; Tenant = tenant; User = user; Scope = scope; Worker = worker; Job = job; Execution = execution; Assessment = assessment; WorkerContext = new(worker.Identity, worker.Capabilities, worker.ApprovedPrivateNetworkRanges); }
        public AppDbContext Db { get; }
        public LoopbackHttpServer Server { get; }
        public Tenant Tenant { get; }
        public User User { get; }
        public TargetScope Scope { get; }
        public WorkerRegistration Worker { get; }
        public AgentJob Job { get; }
        public AgentExecution Execution { get; }
        public WebAssessment Assessment { get; }
        public WorkerExecutionContext WorkerContext { get; }

        public static async Task<AssessmentFixture> CreateAsync()
        {
            var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
            var db = new AppDbContext(options);
            var server = new LoopbackHttpServer();
            var tenant = new Tenant("web authorization tenant");
            var user = new User(tenant.Id, "web-authorization-user", "Test", UserRole.SecurityAnalyst);
            var scope = new TargetScope(tenant.Id, "web authorization scope", user.Id, DateTimeOffset.UtcNow.AddMinutes(5));
            var target = $"http://127.0.0.1:{server.Port}/";
            scope.Configure([new TargetDefinition(TargetKind.Web, target)], [], ["web-assessment-passive"], 100, 120, "controlled-test", false);
            var worker = new WorkerRegistration(tenant.Id, "worker-a", "test", [WebAssessmentCapabilities.WebAssessment]);
            worker.Heartbeat(0, 1);
            var job = new AgentJob(tenant.Id, scope.Id, user.Id, "web-assessment-passive");
            Assert.True(job.TryAcquireLease(worker.Identity, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1)));
            var execution = new AgentExecution(job.Id, "AuthorizedWebAssessmentAgent");
            var assessment = new WebAssessment(tenant.Id, job.Id, scope.Id, target, "web-assessment-passive", WebHostingMode.Public);
            db.AddRange(tenant, user, scope, worker, job, execution, assessment);
            await db.SaveChangesAsync();
            return new AssessmentFixture(db, server, tenant, user, scope, worker, job, execution, assessment);
        }

        public WebAssessmentEngine CreateEngine(IHtmlReportGenerator report)
            => new(Db, new ControlledValidator(), new MemoryArtifactStore(), new ControlledScreenshotService(), report,
                new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["WebAssessment:AuthorizationRefreshIntervalMs"] = "25" }).Build());

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
            IReadOnlyCollection<string> workerCapabilities, IReadOnlyCollection<string>? approvedPrivateNetworkRanges, Func<CancellationToken, Task<bool>> leaseCheck,
            CancellationToken cancellationToken, Func<CancellationToken, Task<WorkerExecutionContext?>>? refreshAuthorization = null)
            => throw new WebAssessmentAuthorizationRevokedException();
    }

    private sealed class ControlledReportGenerator : IHtmlReportGenerator
    {
        public TaskCompletionSource<bool> Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> Cancelled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<string> GenerateAsync(Guid tenantId, WebAssessment assessment, TargetScope scope, CancellationToken cancellationToken)
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

    private sealed class MemoryArtifactStore : IAssessmentArtifactStore
    {
        public Task<string> PutAsync(Guid tenantId, Guid assessmentId, string name, byte[] content, CancellationToken cancellationToken) => Task.FromResult($"{tenantId}/{assessmentId}/{name}");
        public Task<byte[]?> GetAsync(Guid tenantId, string storageKey, CancellationToken cancellationToken) => Task.FromResult<byte[]?>([137, 80, 78, 71]);
    }

    private sealed class LoopbackHttpServer : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly Task loop;
        public LoopbackHttpServer()
        {
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            loop = ServeAsync();
        }
        public int Port { get; }
        private async Task ServeAsync()
        {
            try
            {
                while (!shutdown.IsCancellationRequested)
                {
                    using var client = await listener.AcceptTcpClientAsync(shutdown.Token);
                    using var stream = client.GetStream();
                    var buffer = new byte[4096];
                    _ = await stream.ReadAsync(buffer, shutdown.Token);
                    var body = Encoding.UTF8.GetBytes("<html><body>ok</body></html>");
                    var header = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
                    await stream.WriteAsync(header, shutdown.Token);
                    await stream.WriteAsync(body, shutdown.Token);
                }
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            catch (SocketException) when (shutdown.IsCancellationRequested) { }
        }
        public async ValueTask DisposeAsync()
        {
            shutdown.Cancel();
            listener.Stop();
            try { await loop; } catch (ObjectDisposedException) { }
            shutdown.Dispose();
        }
    }
}
