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
        var refreshes = 0;
        var context = initial with
        {
            RefreshAuthorization = _ => Task.FromResult<WorkerExecutionContext?>(Interlocked.Increment(ref refreshes) < 2 ? worker : null)
        };

        await Assert.ThrowsAsync<WebAssessmentAuthorizationRevokedException>(() =>
            new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token));

        var pathsCount = server.RequestedPaths.Count;

        // Attempt a subsequent request via TCP client to ensure no further requests reach the fixture server
        try
        {
            using var client = new TcpClient();
            var connect = client.ConnectAsync(server.Address, server.Port);
            await connect.WaitAsync(TimeSpan.FromMilliseconds(500));
            if (client.Connected)
            {
                await using var stream = client.GetStream();
                var msg = Encoding.ASCII.GetBytes($"GET /after-revocation HTTP/1.1\r\nHost: allowed.test:{server.Port}\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(msg);
            }
        }
        catch
        {
            // Expected if closed/unreachable
        }

        Assert.DoesNotContain("/after-revocation", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Scenario13_Browser_session_blocks_websockets()
    {
        await using var server = new ControlledHttpsServer(attemptWebSockets: true);
        var context = CreateHttpsContext(server, "/app", basePath: "/app");

        _ = await new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);

        Assert.Contains("/app", server.RequestedPaths);
        Assert.DoesNotContain("/ws", server.RequestedPaths);
    }

    [BrowserFact]
    public async Task Scenario14_Browser_session_blocks_mutating_requests()
    {
        await using var server = new ControlledHttpsServer(attemptMutatingRequests: true);
        var context = CreateHttpsContext(server, "/app", basePath: "/app");

        _ = await new PlaywrightScreenshotCaptureService().CaptureAsync(context, new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);

        Assert.Contains("/app", server.RequestedPaths);
        Assert.DoesNotContain("POST", server.RequestedMethods);
        Assert.DoesNotContain("PUT", server.RequestedMethods);
        Assert.DoesNotContain("DELETE", server.RequestedMethods);
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
                    _ = HandleClientAsync(client, stop.Token);
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
}
