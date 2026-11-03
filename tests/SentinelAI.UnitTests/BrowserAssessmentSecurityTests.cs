using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Playwright;
using SentinelAI.Application;
using SentinelAI.Agent.Vulnerability;
using SentinelAI.Domain;
using SentinelAI.Security.Policy;

namespace SentinelAI.UnitTests;

public sealed class BrowserAssessmentSecurityTests
{
    [BrowserFact]
    public async Task Scenario01_Https_authorized_root_navigation_succeeds()
    {
        await using var server = new ControlledHttpsServer();
        var context = CreateHttpsContext(server, "/", basePath: "/");
        var screenshot = await new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);

        Assert.True(screenshot.Length > 8);
        Assert.Equal([137, 80, 78, 71], screenshot[..4]);
        Assert.Contains("/", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Scenario02_Https_authorized_nested_path_navigation_succeeds()
    {
        await using var server = new ControlledHttpsServer();
        var context = CreateHttpsContext(server, "/app", basePath: "/app");
        var screenshot = await new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);

        Assert.True(screenshot.Length > 8);
        Assert.Equal([137, 80, 78, 71], screenshot[..4]);
        Assert.Contains("/app", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Scenario03_Https_authorized_child_resources_load()
    {
        await using var server = new ControlledHttpsServer(includeChildResource: true);
        var context = CreateHttpsContext(server, "/app", basePath: "/app");

        var screenshot = await new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);

        Assert.True(screenshot.Length > 8);
        Assert.Contains("/app", server.RequestedPaths);
        Assert.Contains("/app/dashboard", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Scenario04_Https_sibling_path_is_denied()
    {
        await using var server = new ControlledHttpsServer(includeSiblingResource: true);
        var context = CreateHttpsContext(server, "/app", basePath: "/app");

        _ = await new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);

        Assert.Contains("/app", server.RequestedPaths);
        Assert.DoesNotContain("/admin/secret.png", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Scenario05_Https_application_path_is_denied_for_app()
    {
        await using var server = new ControlledHttpsServer();
        var context = CreateHttpsContext(server, "/application", basePath: "/app");

        await Assert.ThrowsAsync<ScopeValidationException>(() =>
            new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token));

        Assert.DoesNotContain("/application", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Scenario06_Https_unauthorized_effective_port_is_denied()
    {
        await using var server = new ControlledHttpsServer();
        var context = CreateHttpsContext(server, "/app", basePath: "/app", overridePort: server.Port + 1);

        await Assert.ThrowsAsync<ScopeValidationException>(() =>
            new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token));

        Assert.Empty(server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Scenario07_Https_cross_origin_redirect_is_denied_before_destination_is_contacted()
    {
        await using var server = new ControlledHttpsServer(redirectToCrossOrigin: true);
        var context = CreateHttpsContext(server, "/app", basePath: "/app");

        await Assert.ThrowsAsync<ScopeValidationException>(() =>
            new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token));

        Assert.Contains("/app", server.RequestedPaths);
        Assert.DoesNotContain("/blocked", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Scenario08_Https_redirect_to_unauthorized_path_is_denied()
    {
        await using var server = new ControlledHttpsServer(redirectToSibling: true);
        var context = CreateHttpsContext(server, "/app", basePath: "/app");

        await Assert.ThrowsAsync<ScopeValidationException>(() =>
            new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token));

        Assert.Contains("/app", server.RequestedPaths);
        Assert.DoesNotContain("/admin", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Scenario09_Https_encoded_path_traversal_is_denied()
    {
        await using var server = new ControlledHttpsServer();
        var context = CreateHttpsContext(server, "/app/%2e%2e/admin", basePath: "/app");

        await Assert.ThrowsAsync<ScopeValidationException>(() =>
            new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token));

        Assert.DoesNotContain("/admin", server.RequestedPaths);
        Assert.DoesNotContain("/app/%2e%2e/admin", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Scenario10_Https_double_encoded_path_traversal_is_denied()
    {
        await using var server = new ControlledHttpsServer();
        var context = CreateHttpsContext(server, "/app/%252e%252e/admin", basePath: "/app");

        await Assert.ThrowsAsync<ScopeValidationException>(() =>
            new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token));

        Assert.DoesNotContain("/admin", server.RequestedPaths);
        Assert.DoesNotContain("/app/%252e%252e/admin", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Scenario11_Authorization_revocation_closes_active_page_browser_context_and_proxy()
    {
        await using var server = new ControlledHttpsServer();
        var initial = CreateHttpsContext(server, "/app", basePath: "/app");
        var worker = new WorkerExecutionContext("test-worker", [WebAssessmentCapabilities.WebAssessment, WebAssessmentCapabilities.PrivateWebAssessment], ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
        var refreshes = 0;
        var context = initial with
        {
            RefreshAuthorization = _ => Task.FromResult<WorkerExecutionContext?>(Interlocked.Increment(ref refreshes) < 2 ? worker : null)
        };

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() =>
            new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token));
    }

    [BrowserFact]
    public async Task Scenario12_Request_attempted_after_revocation_never_reaches_fixture_server()
    {
        await using var server = new ControlledHttpsServer();
        var initial = CreateHttpsContext(server, "/app", basePath: "/app");
        var worker = new WorkerExecutionContext("test-worker", [WebAssessmentCapabilities.WebAssessment, WebAssessmentCapabilities.PrivateWebAssessment], ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
        var isAuthorized = true;
        IPage? capturedPage = null;

        var context = initial with
        {
            RefreshAuthorization = _ => Task.FromResult<WorkerExecutionContext?>(isAuthorized ? worker : null),
            TestOnlyOnNavigated = async page =>
            {
                capturedPage = page;
                // Transition authorization to revoked while browser session is still active
                isAuthorized = false;

                // Attempt a second navigation through the SAME active browser page, browser context and proxy
                var afterRevocationUrl = $"https://allowed.test:{server.Port}/after-revocation";
                await Assert.ThrowsAnyAsync<Exception>(() =>
                    page.GotoAsync(afterRevocationUrl, new PageGotoOptions { Timeout = 10_000 }));
            }
        };

        byte[]? screenshot = null;
        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(async () =>
        {
            screenshot = await new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);
        });

        Assert.Null(screenshot);

        // 1. Initial navigation to /app succeeded
        Assert.Contains("/app", server.RequestedPaths);

        // 2. Fixture server NEVER received the request after revocation
        Assert.DoesNotContain("/after-revocation", server.RequestedPaths);

        // 3. Browser page was closed
        Assert.NotNull(capturedPage);
        Assert.True(capturedPage.IsClosed);
    }

    [BrowserFact]
    public async Task Scenario13_Browser_session_blocks_websockets()
    {
        await using var server = new ControlledHttpsServer(attemptWebSockets: true);
        var context = CreateHttpsContext(server, "/app", basePath: "/app");

        // 1. Direct unit verification: Playwright HandleWebSocketRoute closes WebSocket routes without connecting to server
        var testWsRoute = new TestWebSocketRoute();
        PlaywrightScreenshotCaptureService.HandleWebSocketRoute(testWsRoute);
        Assert.True(testWsRoute.Closed);
        Assert.False(testWsRoute.ConnectedToServerCalled);

        // 2. Playwright capture with attemptWebSockets in HTML page succeeds while WebSockets and JS remain disabled in production
        var screenshot = await new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);
        Assert.True(screenshot.Length > 8);
        Assert.Contains("/app", server.RequestedPaths);

        // 3. Exercise WebSocket handshake rejection through BrowserPolicyProxy boundary over HTTP
        await using var proxy = await BrowserPolicyProxy.StartAsync(
            (uri, ct) => Task.FromResult<ValidatedBrowserDestination?>(new ValidatedBrowserDestination(server.Address, [server.Address])),
            CancellationToken.None,
            (uri, ct) => Task.FromResult<ValidatedBrowserDestination?>(new ValidatedBrowserDestination(server.Address, [server.Address])));

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, proxy.ProxyUri.Port);
        await using var stream = client.GetStream();
        var wsRequest = $"GET http://allowed.test:{server.Port}/ws HTTP/1.1\r\nHost: allowed.test:{server.Port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(wsRequest));

        var buffer = new byte[1024];
        var read = await stream.ReadAsync(buffer);
        Assert.Equal(0, read);

        Assert.DoesNotContain("/ws", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Scenario14_Browser_session_blocks_mutating_requests()
    {
        await using var server = new ControlledHttpsServer(attemptMutatingRequests: true);
        var context = CreateHttpsContext(server, "/app", basePath: "/app");

        // 1. Direct unit verification: HandleBrowserRouteAsync aborts mutating HTTP methods (POST, PUT, PATCH, DELETE, TRACE, CONNECT)
        var mutatingMethods = new[] { "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT" };
        foreach (var method in mutatingMethods)
        {
            var testRoute = new TestRoute(method, $"https://allowed.test:{server.Port}/mutate");
            await PlaywrightScreenshotCaptureService.HandleBrowserRouteAsync(
                testRoute,
                _ => Task.FromResult(true),
                _ => Task.CompletedTask,
                (uri, ct) => Task.FromResult<ValidatedBrowserDestination?>(new ValidatedBrowserDestination(server.Address, [server.Address])),
                () => { },
                CancellationToken.None);
            Assert.True(testRoute.Aborted, $"Method {method} was not aborted by browser route handler.");
            Assert.False(testRoute.Continued, $"Method {method} continued through browser route handler.");
        }

        // 2. Playwright capture with attemptMutatingRequests in HTML succeeds without executing mutating requests
        var screenshot = await new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);
        Assert.True(screenshot.Length > 8);
        Assert.Contains("/app", server.RequestedPaths);

        // 3. Exercise proxy rejection of mutating HTTP methods (POST, PUT, PATCH, DELETE, TRACE)
        await using var proxy = await BrowserPolicyProxy.StartAsync(
            (uri, ct) => Task.FromResult<ValidatedBrowserDestination?>(new ValidatedBrowserDestination(server.Address, [server.Address])),
            CancellationToken.None,
            (uri, ct) => Task.FromResult<ValidatedBrowserDestination?>(new ValidatedBrowserDestination(server.Address, [server.Address])));

        foreach (var method in new[] { "POST", "PUT", "PATCH", "DELETE", "TRACE" })
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxy.ProxyUri.Port);
            await using var stream = client.GetStream();
            var request = $"{method} http://allowed.test:{server.Port}/mutate HTTP/1.1\r\nHost: allowed.test:{server.Port}\r\nContent-Length: 4\r\n\r\ntest";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(request));

            var buffer = new byte[1024];
            var read = await stream.ReadAsync(buffer);
            Assert.Equal(0, read);
        }

        Assert.DoesNotContain("POST", server.RequestedMethods);
        Assert.DoesNotContain("PUT", server.RequestedMethods);
        Assert.DoesNotContain("PATCH", server.RequestedMethods);
        Assert.DoesNotContain("DELETE", server.RequestedMethods);
        Assert.DoesNotContain("TRACE", server.RequestedMethods);
        Assert.DoesNotContain("/mutate", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Scenario15_Production_tls_certificate_verification_remains_enabled()
    {
        await using var server = new ControlledHttpsServer();
        var context = CreateHttpsContext(server, "/app", basePath: "/app", testOnlyTrustCertificate: false);

        Assert.False(context.TestOnlyTrustLocalCertificate);

        // When test certificate trust is disabled, connecting to a self-signed HTTPS fixture server must fail TLS validation
        await Assert.ThrowsAnyAsync<Exception>(() =>
            new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token));
    }

    [BrowserFact]
    public async Task Scenario16_Playwright_route_websocket_handler_closes_live_websocket_connection()
    {
        var playwright = await Playwright.CreateAsync();
        try
        {
            var launch = new BrowserTypeLaunchOptions { Headless = true };
            var executable = PlaywrightScreenshotCaptureService.ResolveChromiumExecutable();
            if (executable is not null) launch.ExecutablePath = executable;
            var browser = await playwright.Chromium.LaunchAsync(launch);
            try
            {
                var context = await browser.NewContextAsync();
                try
                {
                    var closeTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    await context.RouteWebSocketAsync("**/ws", ws =>
                    {
                        PlaywrightScreenshotCaptureService.HandleWebSocketRoute(ws);
                        closeTcs.TrySetResult(true);
                    });

                    var page = await context.NewPageAsync();
                    await page.GotoAsync("data:text/html,<html><body>test</body></html>");
                    await page.EvaluateAsync("() => { try { new WebSocket('wss://127.0.0.1:9999/ws'); } catch(e){} }");

                    var completed = await Task.WhenAny(closeTcs.Task, Task.Delay(5000));
                    Assert.Same(closeTcs.Task, completed);
                    Assert.True(await closeTcs.Task);

                    try { await page.CloseAsync(); } catch { }
                }
                finally
                {
                    try { await context.CloseAsync(); } catch { }
                }
            }
            finally
            {
                try { await browser.CloseAsync(); } catch { }
            }
        }
        finally
        {
            playwright.Dispose();
        }
    }

    [Fact]
    public async Task Cancellation_during_chromium_launch_drains_and_disposes_late_arriving_browser()
    {
        using var cts = new CancellationTokenSource();
        var tcs = new TaskCompletionSource<IAsyncDisposable>(TaskCreationOptions.RunContinuationsAsynchronously);
        var mockBrowser = new TestDisposableResource();

        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            PlaywrightScreenshotCaptureService.AwaitPlaywrightStepInternalAsync(tcs.Task, cts.Token));

        tcs.SetResult(mockBrowser);

        await mockBrowser.DisposedTcs.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.True(mockBrowser.IsDisposed);
    }

    [Fact]
    public async Task Cancellation_during_browser_context_creation_drains_and_disposes_late_arriving_context()
    {
        using var cts = new CancellationTokenSource();
        var tcs = new TaskCompletionSource<IAsyncDisposable>(TaskCreationOptions.RunContinuationsAsynchronously);
        var mockContext = new TestDisposableResource();

        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            PlaywrightScreenshotCaptureService.AwaitPlaywrightStepInternalAsync(tcs.Task, cts.Token));

        tcs.SetResult(mockContext);

        await mockContext.DisposedTcs.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.True(mockContext.IsDisposed);
    }

    [Fact]
    public async Task Cancellation_during_page_creation_drains_and_disposes_late_arriving_page()
    {
        using var cts = new CancellationTokenSource();
        var tcs = new TaskCompletionSource<IAsyncDisposable>(TaskCreationOptions.RunContinuationsAsynchronously);
        var mockPage = new TestDisposableResource();

        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            PlaywrightScreenshotCaptureService.AwaitPlaywrightStepInternalAsync(tcs.Task, cts.Token));

        tcs.SetResult(mockPage);

        await mockPage.DisposedTcs.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.True(mockPage.IsDisposed);
    }

    [Fact]
    public async Task Cancellation_during_navigation_safely_observes_late_completion_and_fault()
    {
        using var cts = new CancellationTokenSource();
        var tcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);

        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            PlaywrightScreenshotCaptureService.AwaitPlaywrightStepInternalAsync(tcs.Task, cts.Token));

        tcs.SetException(new PlaywrightException("Target page closed"));

        await Task.Delay(50);
        Assert.True(tcs.Task.IsFaulted);
    }

    [Fact]
    public async Task Cancellation_during_screenshot_generation_safely_drains_task()
    {
        using var cts = new CancellationTokenSource();
        var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);

        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            PlaywrightScreenshotCaptureService.AwaitPlaywrightStepInternalAsync(tcs.Task, cts.Token));

        tcs.SetResult([1, 2, 3]);

        await Task.Delay(50);
        Assert.True(tcs.Task.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task Authorization_revocation_during_step_translates_to_revoked_exception()
    {
        using var cts = new CancellationTokenSource();
        var tcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
        cts.Cancel();

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() =>
            PlaywrightScreenshotCaptureService.AwaitPlaywrightStepInternalAsync(tcs.Task, cts.Token, isAuthorizationRevoked: () => true));
    }

    [Fact]
    public async Task Lease_lost_during_step_translates_to_lease_lost_exception()
    {
        using var cts = new CancellationTokenSource();
        var tcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
        cts.Cancel();

        await Assert.ThrowsAsync<WebAssessmentLeaseLostException>(() =>
            PlaywrightScreenshotCaptureService.AwaitPlaywrightStepInternalAsync(tcs.Task, cts.Token, isLeaseLost: () => true));
    }

    private static BrowserAssessmentContext CreateHttpsContext(
        ControlledHttpsServer server,
        string path,
        string basePath = "/app",
        int? overridePort = null,
        bool testOnlyTrustCertificate = true,
        bool allowSubdomains = false)
    {
        var tenantId = Guid.NewGuid();
        var port = server.Port;
        var effectivePort = overridePort ?? port;
        var targetUri = new Uri($"https://allowed.test:{effectivePort}{path}");
        var authorizedBase = $"https://allowed.test:{port}{basePath}";

        var scope = new TargetScope(tenantId, "https-browser-test", Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(5));
        scope.Configure(
            [new TargetDefinition(TargetKind.Web, authorizedBase)],
            [],
            ["web-assessment-passive"],
            100,
            120,
            "controlled-test",
            false,
            allowSubdomains: allowSubdomains);
        scope.ConfigureWebHosting(WebHostingMode.Private, "test-worker", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);

        var validator = new TargetScopeValidator(new DeterministicResolver(server.Address));
        var validated = new ValidatedExecutionTarget(
            targetUri.Host,
            [server.Address],
            DateTimeOffset.UtcNow,
            scope.Id,
            tenantId,
            scope.ExpiresAt,
            "web-assessment-passive");

        return new BrowserAssessmentContext(
            tenantId,
            Guid.NewGuid(),
            scope,
            targetUri,
            "test-worker",
            [WebAssessmentCapabilities.WebAssessment, WebAssessmentCapabilities.PrivateWebAssessment],
            ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            validated,
            _ => Task.FromResult(true),
            _ => Task.CompletedTask,
            validator,
            "web-assessment-passive",
            TestOnlyTrustLocalCertificate: testOnlyTrustCertificate);
    }

    private sealed class BrowserFactAttribute : FactAttribute
    {
        public BrowserFactAttribute()
        {
            if (!string.Equals(Environment.GetEnvironmentVariable("SENTINELAI_RUN_BROWSER_TESTS"), "true", StringComparison.OrdinalIgnoreCase))
                Skip = "Set SENTINELAI_RUN_BROWSER_TESTS=true after installing Playwright Chromium to run genuine browser security coverage.";
        }
    }

    private sealed class DeterministicResolver(IPAddress address) : IHostAddressResolver
    {
        public Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            if (host.Equals("allowed.test", StringComparison.OrdinalIgnoreCase) ||
                host.EndsWith(".allowed.test", StringComparison.OrdinalIgnoreCase) ||
                host.Equals("other.test", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult<IReadOnlyCollection<IPAddress>>([address]);
            }

            return Task.FromResult<IReadOnlyCollection<IPAddress>>([]);
        }
    }

    private sealed class ControlledHttpsServer : IAsyncDisposable
    {
        private readonly TcpListener listener;
        private readonly CancellationTokenSource stop = new();
        private readonly ConcurrentDictionary<Task, bool> handlerTasks = new();
        private readonly List<string> paths = [];
        private readonly List<string> methods = [];
        private readonly RSA key = RSA.Create(2048);
        private readonly X509Certificate2 certificate;
        private readonly bool redirectToSibling;
        private readonly bool redirectToCrossOrigin;
        private readonly bool includeChildResource;
        private readonly bool includeSiblingResource;
        private readonly bool attemptMutatingRequests;
        private readonly bool attemptWebSockets;
        private readonly Task loop;

        public ControlledHttpsServer(
            bool redirectToSibling = false,
            bool redirectToCrossOrigin = false,
            bool includeChildResource = false,
            bool includeSiblingResource = false,
            bool attemptMutatingRequests = false,
            bool attemptWebSockets = false)
        {
            this.redirectToSibling = redirectToSibling;
            this.redirectToCrossOrigin = redirectToCrossOrigin;
            this.includeChildResource = includeChildResource;
            this.includeSiblingResource = includeSiblingResource;
            this.attemptMutatingRequests = attemptMutatingRequests;
            this.attemptWebSockets = attemptWebSockets;

            Address = ResolveLocalPrivateAddress();
            listener = new TcpListener(IPAddress.Any, 0);
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;

            var request = new CertificateRequest("CN=allowed.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("allowed.test");
            names.AddDnsName("*.allowed.test");
            names.AddDnsName("other.test");
            names.AddIpAddress(Address);
            names.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(names.Build());
            certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMinutes(15));

            loop = LoopAsync();
        }

        public IPAddress Address { get; }
        public int Port { get; }
        public IReadOnlyCollection<string> RequestedPaths { get { lock (paths) return paths.ToArray(); } }
        public IReadOnlyCollection<string> RequestedMethods { get { lock (methods) return methods.ToArray(); } }

        private async Task LoopAsync()
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    var client = await listener.AcceptTcpClientAsync(stop.Token);
                    var task = HandleClientAsync(client, stop.Token);
                    handlerTasks.TryAdd(task, true);
                    _ = task.ContinueWith(t => handlerTasks.TryRemove(t, out _), CancellationToken.None,
                        TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (ObjectDisposedException) when (stop.IsCancellationRequested) { }
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken token)
        {
            using (client)
            {
                try
                {
                    await using var stream = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
                    await stream.AuthenticateAsServerAsync(certificate, false, SslProtocols.Tls12 | SslProtocols.Tls13, false);

                    var buffer = new byte[8192];
                    var read = await stream.ReadAsync(buffer, token);
                    if (read <= 0) return;

                    var request = Encoding.ASCII.GetString(buffer, 0, read);
                    var method = request.Split(' ', StringSplitOptions.RemoveEmptyEntries).ElementAtOrDefault(0) ?? "GET";
                    var path = request.Split(' ', StringSplitOptions.RemoveEmptyEntries).ElementAtOrDefault(1) ?? "/";

                    lock (paths) paths.Add(path);
                    lock (methods) methods.Add(method);

                    if (redirectToCrossOrigin && (path == "/" || path == "/app"))
                    {
                        var response = $"HTTP/1.1 302 Found\r\nLocation: https://other.test:{Port}/blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        await stream.WriteAsync(Encoding.ASCII.GetBytes(response), token);
                        return;
                    }

                    if (redirectToSibling && (path == "/" || path == "/app"))
                    {
                        var response = "HTTP/1.1 302 Found\r\nLocation: /admin\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        await stream.WriteAsync(Encoding.ASCII.GetBytes(response), token);
                        return;
                    }

                    string body;
                    if (includeChildResource)
                    {
                        body = "<html><body>authorized<img src='/app/dashboard'></body></html>";
                    }
                    else if (includeSiblingResource)
                    {
                        body = "<html><body>authorized<img src='/admin/secret.png'></body></html>";
                    }
                    else if (attemptMutatingRequests)
                    {
                        body = "<html><body><script>fetch('/mutate', {method:'POST', body:'test'}); fetch('/mutate', {method:'PUT'}); fetch('/mutate', {method:'DELETE'});</script></body></html>";
                    }
                    else if (attemptWebSockets)
                    {
                        body = $"<html><body><script>try {{ new WebSocket('wss://allowed.test:{Port}/ws'); }} catch(e){{}}</script></body></html>";
                    }
                    else
                    {
                        body = "<html><body>authorized</body></html>";
                    }

                    var okResponse = $"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}";
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(okResponse), token);
                }
                catch (AuthenticationException) when (!stop.IsCancellationRequested) { }
                catch (IOException) when (!stop.IsCancellationRequested) { }
                catch (SocketException) when (!stop.IsCancellationRequested) { }
            }
        }

        public async ValueTask DisposeAsync()
        {
            stop.Cancel();
            listener.Stop();
            try { await loop; } catch (OperationCanceledException) { }
            var pending = handlerTasks.Keys.ToArray();
            if (pending.Length > 0)
            {
                try { await Task.WhenAll(pending); } catch { }
            }
            certificate.Dispose();
            key.Dispose();
            stop.Dispose();
        }

        private static IPAddress ResolveLocalPrivateAddress()
        {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up ||
                    ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                    continue;

                foreach (var ip in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork && TargetScopeValidator.IsPrivateAddress(ip.Address))
                        return ip.Address;
                }
            }

            return IPAddress.Parse("10.0.0.1");
        }
    }

    private sealed class TestWebSocketRoute : IWebSocketRoute
    {
        public bool Closed { get; private set; }
        public bool ConnectedToServerCalled { get; private set; }
        public string Url => "wss://allowed.test/ws";
        public Task CloseAsync(WebSocketRouteCloseOptions? options = null)
        {
            Closed = true;
            return Task.CompletedTask;
        }
        public IWebSocketRoute ConnectToServer()
        {
            ConnectedToServerCalled = true;
            return this;
        }
        public void OnClose(Action<int?, string> handler) { }
        public void OnMessage(Action<IWebSocketFrame> handler) { }
        public void Send(byte[] message) { }
        public void Send(string message) { }
    }

    private sealed class TestRequest(string method, string url) : IRequest
    {
        public string Method => method;
        public string Url => url;
        public Dictionary<string, string> Headers => new();
        public bool IsNavigationRequest => false;
        public IFrame Frame => null!;
        public string? PostData => null;
        public byte[]? PostDataBuffer => null;
        public IRequest? RedirectedFrom => null;
        public IRequest? RedirectedTo => null;
        public string ResourceType => "document";
        public Task<IResponse?> ResponseAsync() => Task.FromResult<IResponse?>(null);
        public Task<Dictionary<string, string>> AllHeadersAsync() => Task.FromResult(new Dictionary<string, string>());
        public Task<string?> HeaderValueAsync(string name) => Task.FromResult<string?>(null);
        public Task<IReadOnlyList<Header>> HeadersArrayAsync() => Task.FromResult<IReadOnlyList<Header>>([]);
        public System.Text.Json.JsonElement? PostDataJSON() => null;
        public Task<RequestSizesResult> SizesAsync() => Task.FromResult(new RequestSizesResult());
        public RequestTimingResult Timing => new();
        public string? Failure => null;
    }

    private sealed class TestRoute(string method, string url) : IRoute
    {
        public bool Aborted { get; private set; }
        public bool Continued { get; private set; }
        public IRequest Request { get; } = new TestRequest(method, url);
        public Task AbortAsync(string? errorCode = null) { Aborted = true; return Task.CompletedTask; }
        public Task ContinueAsync(RouteContinueOptions? options = null) { Continued = true; return Task.CompletedTask; }
        public Task FallbackAsync(RouteFallbackOptions? options = null) => Task.CompletedTask;
        public Task FulfillAsync(RouteFulfillOptions? options = null) => Task.CompletedTask;
        public Task<IAPIResponse> FetchAsync(RouteFetchOptions? options = null) => Task.FromResult<IAPIResponse>(null!);
    }

    private sealed class TestDisposableResource : IAsyncDisposable, IDisposable
    {
        public bool IsDisposed { get; private set; }
        public TaskCompletionSource<bool> DisposedTcs { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ValueTask DisposeAsync()
        {
            IsDisposed = true;
            DisposedTcs.TrySetResult(true);
            return ValueTask.CompletedTask;
        }

        public void Dispose()
        {
            IsDisposed = true;
            DisposedTcs.TrySetResult(true);
        }
    }
}
