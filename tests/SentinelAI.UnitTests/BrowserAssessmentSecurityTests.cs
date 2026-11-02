using System.Net;
using System.Net.Sockets;
using System.Text;
using SentinelAI.Agent.Vulnerability;
using SentinelAI.Domain;
using SentinelAI.Security.Policy;

namespace SentinelAI.UnitTests;

public sealed class BrowserAssessmentSecurityTests
{
    [BrowserFact]
    public async Task Browser_session_captures_a_real_png_and_blocks_an_out_of_scope_subresource()
    {
        var browser = "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser";
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SENTINELAI_PLAYWRIGHT_EXECUTABLE")) && File.Exists(browser)) Environment.SetEnvironmentVariable("SENTINELAI_PLAYWRIGHT_EXECUTABLE", browser);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var server = new ControlledHttpServer();
        var tenantId = Guid.NewGuid();
        var scope = new TargetScope(tenantId, "browser-test", Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(5));
        var target = new Uri($"http://allowed.test:{server.Port}/");
        scope.Configure([new TargetDefinition(TargetKind.Web, target.ToString())], [], ["web-assessment-passive"], 100, 120, "controlled-test", false);
        var validated = new ValidatedExecutionTarget(target.Host, [IPAddress.Loopback], DateTimeOffset.UtcNow, scope.Id, tenantId, scope.ExpiresAt, "web-assessment-passive");
        var context = new BrowserAssessmentContext(tenantId, Guid.NewGuid(), scope, target, "test-worker", ["web-assessment"], [], validated,
            _ => Task.FromResult(true), _ => Task.CompletedTask, new ControlledValidator(target, validated), "web-assessment-passive");

        var screenshot = await new PlaywrightScreenshotCaptureService().CaptureAsync(context, cancellation.Token);

        Assert.True(screenshot.Length > 8);
        Assert.Equal([137, 80, 78, 71], screenshot[..4]);
        Assert.Contains("/", server.RequestedPaths);
        Assert.DoesNotContain("/blocked.png", server.RequestedPaths);
    }

    private sealed class BrowserFactAttribute : FactAttribute
    {
        public BrowserFactAttribute()
        {
            if (!string.Equals(Environment.GetEnvironmentVariable("SENTINELAI_RUN_BROWSER_TESTS"), "true", StringComparison.OrdinalIgnoreCase))
                Skip = "Set SENTINELAI_RUN_BROWSER_TESTS=true after installing Playwright Chromium to run genuine browser security coverage.";
        }
    }

    private sealed class ControlledValidator(Uri allowed, ValidatedExecutionTarget validated) : ITargetScopeValidator
    {
        public ScopeValidationResult ValidateDefinition(TargetScope scope, Guid tenantId, DateTimeOffset now) => ScopeValidationResult.Valid();
        public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, string target, string operationProfile, CancellationToken cancellationToken = default)
            => ValidateExecutionAsync(scope, tenantId, TargetKind.Network, target, operationProfile, null, cancellationToken);
        public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, TargetKind kind, string target, string operationProfile, CancellationToken cancellationToken = default)
            => ValidateExecutionAsync(scope, tenantId, kind, target, operationProfile, null, cancellationToken);
        public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, TargetKind kind, string target, string operationProfile, WorkerExecutionContext? worker, CancellationToken cancellationToken = default)
            => Uri.TryCreate(target, UriKind.Absolute, out var uri) && uri.Host.Equals(allowed.Host, StringComparison.OrdinalIgnoreCase) && uri.Port == allowed.Port
                ? ValueTask.FromResult(ScopeValidationResult.Valid(validated))
                : ValueTask.FromResult(ScopeValidationResult.Invalid("Out of scope test destination."));
        public ValueTask<ScopeValidationResult> ValidateRedirectAsync(TargetScope scope, Guid tenantId, Uri redirect, string operationProfile, CancellationToken cancellationToken = default)
            => ValidateExecutionAsync(scope, tenantId, TargetKind.Web, redirect.ToString(), operationProfile, cancellationToken);
    }

    private sealed class ControlledHttpServer : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource stop = new();
        private readonly List<string> paths = [];
        private readonly Task loop;
        public ControlledHttpServer() { listener.Start(); Port = ((IPEndPoint)listener.LocalEndpoint).Port; loop = LoopAsync(); }
        public int Port { get; }
        public IReadOnlyCollection<string> RequestedPaths { get { lock (paths) return paths.ToArray(); } }
        private async Task LoopAsync()
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    using var client = await listener.AcceptTcpClientAsync(stop.Token);
                    using var stream = client.GetStream();
                    var buffer = new byte[8192];
                    var read = await stream.ReadAsync(buffer, stop.Token);
                    var request = Encoding.ASCII.GetString(buffer, 0, read);
                    var path = request.Split(' ', StringSplitOptions.RemoveEmptyEntries).ElementAtOrDefault(1) ?? "/";
                    lock (paths) paths.Add(path);
                    var body = path == "/" ? "<html><body><input type='password' value='secret'><span data-sensitive>token-value</span><img src='http://blocked.test/blocked.png'></body></html>" : "blocked";
                    var response = $"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}";
                    await stream.WriteAsync(Encoding.UTF8.GetBytes(response), stop.Token);
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (ObjectDisposedException) when (stop.IsCancellationRequested) { }
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); listener.Stop(); try { await loop; } catch (OperationCanceledException) { } stop.Dispose(); }
    }
}
