using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SentinelAI.Application;
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

    [BrowserFact]
    public async Task Browser_session_blocks_a_cross_origin_redirect()
    {
        var browser = "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge";
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SENTINELAI_PLAYWRIGHT_EXECUTABLE")) && File.Exists(browser)) Environment.SetEnvironmentVariable("SENTINELAI_PLAYWRIGHT_EXECUTABLE", browser);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var server = new ControlledHttpServer(redirectOutOfScope: true);
        var tenantId = Guid.NewGuid();
        var scope = new TargetScope(tenantId, "redirect-test", Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(5));
        var target = new Uri($"http://allowed.test:{server.Port}/");
        scope.Configure([new TargetDefinition(TargetKind.Web, target.ToString())], [], ["web-assessment-passive"], 100, 120, "controlled-test", false);
        var validated = new ValidatedExecutionTarget(target.Host, [IPAddress.Loopback], DateTimeOffset.UtcNow, scope.Id, tenantId, scope.ExpiresAt, "web-assessment-passive");
        var context = new BrowserAssessmentContext(tenantId, Guid.NewGuid(), scope, target, "test-worker", ["web-assessment"], [], validated,
            _ => Task.FromResult(true), _ => Task.CompletedTask, new ControlledValidator(target, validated), "web-assessment-passive");

        await Assert.ThrowsAnyAsync<Exception>(() => new PlaywrightScreenshotCaptureService().CaptureAsync(context, cancellation.Token));
        Assert.Contains("/", server.RequestedPaths);
        Assert.DoesNotContain("/blocked", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Browser_session_does_not_execute_mutating_script_requests()
    {
        var browser = "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge";
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SENTINELAI_PLAYWRIGHT_EXECUTABLE")) && File.Exists(browser)) Environment.SetEnvironmentVariable("SENTINELAI_PLAYWRIGHT_EXECUTABLE", browser);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var server = new ControlledHttpServer(attemptMutatingRequests: true);
        var tenantId = Guid.NewGuid();
        var scope = new TargetScope(tenantId, "readonly-browser-test", Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(5));
        var target = new Uri($"http://allowed.test:{server.Port}/");
        scope.Configure([new TargetDefinition(TargetKind.Web, target.ToString())], [], ["web-assessment-passive"], 100, 120, "controlled-test", false);
        var validated = new ValidatedExecutionTarget(target.Host, [IPAddress.Loopback], DateTimeOffset.UtcNow, scope.Id, tenantId, scope.ExpiresAt, "web-assessment-passive");
        var context = new BrowserAssessmentContext(tenantId, Guid.NewGuid(), scope, target, "test-worker", ["web-assessment"], [], validated,
            _ => Task.FromResult(true), _ => Task.CompletedTask, new ControlledValidator(target, validated), "web-assessment-passive");

        _ = await new PlaywrightScreenshotCaptureService().CaptureAsync(context, cancellation.Token);

        Assert.DoesNotContain("POST", server.RequestedMethods);
        Assert.DoesNotContain("PUT", server.RequestedMethods);
        Assert.DoesNotContain("DELETE", server.RequestedMethods);
        Assert.DoesNotContain("/mutate", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Https_authorized_root_completes_connect_and_screenshot()
    {
        await using var server = new ControlledHttpsServer();
        var context = CreateHttpsContext(server, "/");
        var screenshot = await new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);

        Assert.True(screenshot.Length > 8);
        Assert.Contains("/", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Https_nested_path_allows_a_child_path()
    {
        await using var server = new ControlledHttpsServer(includeChildResource: true);
        var context = CreateHttpsContext(server, "/app");

        _ = await new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);

        Assert.Contains("/app", server.RequestedPaths);
        Assert.Contains("/app/dashboard", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Https_port_is_part_of_the_authorized_destination()
    {
        await using var server = new ControlledHttpsServer();
        var context = CreateHttpsContext(server, "/", overridePort: server.Port + 1);

        await Assert.ThrowsAnyAsync<Exception>(() => new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token));

        Assert.Empty(server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Https_redirect_to_a_denied_path_is_blocked()
    {
        await using var server = new ControlledHttpsServer(redirectToSibling: true);
        var context = CreateHttpsContext(server, "/app");
        var validator = (ControlledValidator)context.Validator;

        await Assert.ThrowsAsync<ScopeValidationException>(() => new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token));

        Assert.Contains(validator.RequestedTargets, target => target.EndsWith("/admin", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain("/admin", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Authorization_revocation_stops_the_browser_session()
    {
        await using var server = new ControlledHttpsServer();
        var initial = CreateHttpsContext(server, "/");
        var worker = new WorkerExecutionContext("test-worker", ["web-assessment"], []);
        var refreshes = 0;
        var context = initial with
        {
            RefreshAuthorization = _ => Task.FromResult<WorkerExecutionContext?>(Interlocked.Increment(ref refreshes) < 3 ? worker : null)
        };

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() => new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token));

        Assert.DoesNotContain("/blocked", server.RequestedPaths);
    }

    [Fact]
    public async Task Production_context_does_not_enable_test_certificate_trust()
    {
        await using var server = new ControlledHttpsServer();
        var context = CreateHttpsContext(server, "/", testOnlyTrustCertificate: false);
        Assert.False(context.TestOnlyTrustLocalCertificate);
    }

    private static BrowserAssessmentContext CreateHttpsContext(ControlledHttpsServer server, string path, int? overridePort = null, bool testOnlyTrustCertificate = true)
    {
        var tenantId = Guid.NewGuid();
        var port = overridePort ?? server.Port;
        var target = new Uri($"https://allowed.test:{port}{path}");
        var scope = new TargetScope(tenantId, "https-browser-test", Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(5));
        scope.Configure([new TargetDefinition(TargetKind.Web, target.ToString())], [], ["web-assessment-passive"], 100, 120, "controlled-test", false);
        var validated = new ValidatedExecutionTarget(target.Host, [IPAddress.Loopback], DateTimeOffset.UtcNow, scope.Id, tenantId, scope.ExpiresAt, "web-assessment-passive");
        return new BrowserAssessmentContext(tenantId, Guid.NewGuid(), scope, target, "test-worker", ["web-assessment"], [], validated,
            _ => Task.FromResult(true), _ => Task.CompletedTask, new ControlledValidator(target, validated), "web-assessment-passive", TestOnlyTrustLocalCertificate: testOnlyTrustCertificate);
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
        private readonly List<string> requestedTargets = [];
        public IReadOnlyCollection<string> RequestedTargets { get { lock (requestedTargets) return requestedTargets.ToArray(); } }
        public ScopeValidationResult ValidateDefinition(TargetScope scope, Guid tenantId, DateTimeOffset now) => ScopeValidationResult.Valid();
        public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, string target, string operationProfile, CancellationToken cancellationToken = default)
            => ValidateExecutionAsync(scope, tenantId, TargetKind.Network, target, operationProfile, null, cancellationToken);
        public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, TargetKind kind, string target, string operationProfile, CancellationToken cancellationToken = default)
            => ValidateExecutionAsync(scope, tenantId, kind, target, operationProfile, null, cancellationToken);
        public ValueTask<ScopeValidationResult> ValidateExecutionAsync(TargetScope scope, Guid tenantId, TargetKind kind, string target, string operationProfile, WorkerExecutionContext? worker, CancellationToken cancellationToken = default)
        {
            lock (requestedTargets) requestedTargets.Add(target);
            return Uri.TryCreate(target, UriKind.Absolute, out var uri) && uri.Host.Equals(allowed.Host, StringComparison.OrdinalIgnoreCase) && uri.Port == allowed.Port &&
                (string.IsNullOrEmpty(allowed.AbsolutePath) || uri.AbsolutePath.Equals(allowed.AbsolutePath, StringComparison.OrdinalIgnoreCase) || uri.AbsolutePath.StartsWith(allowed.AbsolutePath.TrimEnd('/') + "/", StringComparison.OrdinalIgnoreCase))
                ? ValueTask.FromResult(ScopeValidationResult.Valid(validated))
                : ValueTask.FromResult(ScopeValidationResult.Invalid("Out of scope test destination."));
        }
        public ValueTask<ScopeValidationResult> ValidateRedirectAsync(TargetScope scope, Guid tenantId, Uri redirect, string operationProfile, CancellationToken cancellationToken = default)
            => ValidateExecutionAsync(scope, tenantId, TargetKind.Web, redirect.ToString(), operationProfile, cancellationToken);
    }

    private sealed class ControlledHttpServer : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource stop = new();
        private readonly List<string> paths = [];
        private readonly Task loop;
        private readonly bool redirectOutOfScope;
        private readonly bool attemptMutatingRequests;
        public ControlledHttpServer(bool redirectOutOfScope = false, bool attemptMutatingRequests = false) { this.redirectOutOfScope = redirectOutOfScope; this.attemptMutatingRequests = attemptMutatingRequests; listener.Start(); Port = ((IPEndPoint)listener.LocalEndpoint).Port; loop = LoopAsync(); }
        public int Port { get; }
        public IReadOnlyCollection<string> RequestedPaths { get { lock (paths) return paths.Select(path => path.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries).ElementAtOrDefault(1) ?? path).ToArray(); } }
        public IReadOnlyCollection<string> RequestedMethods { get { lock (paths) return paths.Select(path => path.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty).ToArray(); } }
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
                    var method = request.Split(' ', StringSplitOptions.RemoveEmptyEntries).ElementAtOrDefault(0) ?? string.Empty;
                    lock (paths) paths.Add($"{method} {path}");
                    var html = attemptMutatingRequests
                        ? "<html><body><input type='password' value='secret'><span data-sensitive>token-value</span><script>fetch('/mutate', {method:'POST', body:'state-change'}); fetch('/mutate', {method:'PUT'}); fetch('/mutate', {method:'DELETE'});</script></body></html>"
                        : "<html><body><input type='password' value='secret'><span data-sensitive>token-value</span><img src='http://blocked.test/blocked.png'></body></html>";
                    var response = redirectOutOfScope && path == "/"
                        ? "HTTP/1.1 302 Found\r\nLocation: http://blocked.test/blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        : $"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {Encoding.UTF8.GetByteCount(path == "/" ? html : "blocked")}\r\nConnection: close\r\n\r\n{(path == "/" ? html : "blocked")}";
                    await stream.WriteAsync(Encoding.UTF8.GetBytes(response), stop.Token);
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (ObjectDisposedException) when (stop.IsCancellationRequested) { }
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); listener.Stop(); try { await loop; } catch (OperationCanceledException) { } stop.Dispose(); }
    }

    private sealed class ControlledHttpsServer : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource stop = new();
        private readonly List<string> paths = [];
        private readonly RSA key = RSA.Create(2048);
        private readonly X509Certificate2 certificate;
        private readonly bool redirectToSibling;
        private readonly bool includeChildResource;
        private readonly Task loop;

        public ControlledHttpsServer(bool redirectToSibling = false, bool includeChildResource = false)
        {
            this.redirectToSibling = redirectToSibling;
            this.includeChildResource = includeChildResource;
            var request = new CertificateRequest("CN=allowed.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("allowed.test");
            request.CertificateExtensions.Add(names.Build());
            certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(10));
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            loop = LoopAsync();
        }

        public int Port { get; }
        public IReadOnlyCollection<string> RequestedPaths { get { lock (paths) return paths.ToArray(); } }

        private async Task LoopAsync()
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    using var client = await listener.AcceptTcpClientAsync(stop.Token);
                    try
                    {
                        await using var stream = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
                        await stream.AuthenticateAsServerAsync(certificate, false, System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, false);
                        var buffer = new byte[8192];
                        var read = await stream.ReadAsync(buffer, stop.Token);
                        var request = Encoding.ASCII.GetString(buffer, 0, read);
                        var path = request.Split(' ', StringSplitOptions.RemoveEmptyEntries).ElementAtOrDefault(1) ?? "/";
                        lock (paths) paths.Add(path);
                        var body = includeChildResource
                            ? "<html><body>authorized<img src='/app/dashboard'></body></html>"
                            : "<html><body>authorized</body></html>";
                        var response = redirectToSibling && path == "/app"
                            ? "HTTP/1.1 302 Found\r\nLocation: /admin\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            : $"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}";
                        await stream.WriteAsync(Encoding.ASCII.GetBytes(response), stop.Token);
                    }
                    catch (AuthenticationException) when (!stop.IsCancellationRequested) { }
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (ObjectDisposedException) when (stop.IsCancellationRequested) { }
        }

        public async ValueTask DisposeAsync()
        {
            stop.Cancel();
            listener.Stop();
            try { await loop; } catch (OperationCanceledException) { }
            certificate.Dispose();
            key.Dispose();
            stop.Dispose();
        }
    }
}
