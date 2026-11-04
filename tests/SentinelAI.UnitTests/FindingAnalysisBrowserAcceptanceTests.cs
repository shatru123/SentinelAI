using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Playwright;
using SentinelAI.Contracts;
using SentinelAI.Domain;

namespace SentinelAI.UnitTests;

public sealed class FindingAnalysisBrowserAcceptanceTests
{
    [Fact]
    public async Task Finding_analysis_browser_workflows_enforce_operator_viewer_provider_and_evidence_boundaries()
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("SENTINELAI_RUN_BROWSER_TESTS"), "true", StringComparison.OrdinalIgnoreCase))
            return;

        var tenantId = Guid.NewGuid();
        var adminId = Guid.NewGuid();
        var analystId = Guid.NewGuid();
        var viewerId = Guid.NewGuid();
        var findingId = Guid.NewGuid();
        var noEvidenceFindingId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;

        var findings = new[]
        {
            new FindingResponse(findingId, "CORS policy weakness", FindingSeverity.High, null, now.AddDays(-1)),
            new FindingResponse(noEvidenceFindingId, "Finding without stored evidence", FindingSeverity.Medium, null, now)
        };
        var details = new ConcurrentDictionary<Guid, FindingDetailResponse>();
        details[findingId] = new FindingDetailResponse(findingId, "CORS policy weakness", FindingSeverity.High,
            null, null, "https://example.test/", "SecurityHeaders", "High", "https://example.test/",
            "GET", null, "The response permits an overly broad cross-origin policy.", "Sensitive responses may be readable cross-origin.",
            null, "Restrict allowed origins.", WebCheckStatus.FindingDetected, now.AddDays(-1),
            [new EvidenceResponse(Guid.NewGuid(), findingId, "header-check", "Observed Access-Control-Allow-Origin: *",
                new string('B', 64), "Access-Control-Allow-Origin: *", "text/plain", now.AddDays(-1))], []);
        details[noEvidenceFindingId] = new FindingDetailResponse(noEvidenceFindingId, "Finding without stored evidence",
            FindingSeverity.Medium, null, null, "https://example.test/", "SecurityHeaders", "Medium",
            "https://example.test/", "GET", null, "A finding without persisted evidence.", "No evidence exists.",
            null, "Collect evidence first.", WebCheckStatus.FindingDetected, now, [], []);

        var analysis = CreateAnalysis(findingId, now);
        var priorAnalysis = CreateAnalysis(findingId, now.AddHours(-2)) with
        {
            Id = Guid.NewGuid(),
            Result = new FindingAIAnalysisResultResponse("Previously saved analysis visible to readers.",
                "The stored evidence supports analyst review.", "Medium", [], ["Browser test uncertainty"])
        };
        var histories = new ConcurrentDictionary<Guid, List<FindingAIAnalysisResponse>>();
        histories[findingId] = [priorAnalysis];
        histories[noEvidenceFindingId] = [];

        var providersConfigured = true;
        var simulateProviderFailure = false;
        var providerStatusCalls = 0;
        var analysisCalls = new ConcurrentDictionary<Guid, int>();

        var apiBuilder = WebApplication.CreateBuilder();
        apiBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        var api = apiBuilder.Build();
        api.MapGet("/api/v1/dashboard/summary", () => Results.Json(new DashboardSummaryResponse(
            0, 0, 0, findings.Length, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, [], [], [])));
        api.MapGet("/api/v1/findings", () => Results.Json(new PagedResponse<FindingResponse>(findings, 1, 25, findings.Length)));
        api.MapGet("/api/v1/findings/{id:guid}", (Guid id) =>
            details.TryGetValue(id, out var detail) ? Results.Json(detail) : Results.NotFound());
        api.MapGet("/api/v1/findings/{id:guid}/ai-analyses", (Guid id) =>
            Results.Json(histories.TryGetValue(id, out var history) ? history : []));
        api.MapGet("/api/v1/ai/providers", () =>
        {
            Interlocked.Increment(ref providerStatusCalls);
            object[] configuredProviders = providersConfigured
                ? [new { provider = "ollama", configured = true, healthy = true }]
                : [];
            return Results.Json(new { selectedProvider = "ollama", providers = configuredProviders });
        });
        api.MapPost("/api/v1/findings/{id:guid}/ai-analysis", async (Guid id, AnalyzeFindingRequest request) =>
        {
            _ = request;
            analysisCalls.AddOrUpdate(id, 1, (_, count) => count + 1);
            if (id == noEvidenceFindingId)
                return Results.Problem("A finding without stored evidence cannot be analyzed.", statusCode: StatusCodes.Status400BadRequest);
            if (simulateProviderFailure)
                return Results.Problem("The configured provider is temporarily unavailable.", statusCode: StatusCodes.Status503ServiceUnavailable);
            var saved = analysis with { Id = Guid.NewGuid(), CreatedAt = DateTimeOffset.UtcNow };
            histories.AddOrUpdate(id, [saved], (_, existing) => [saved, .. existing]);
            return Results.Json(saved);
        });

        await api.StartAsync();
        var apiUrl = api.Services.GetRequiredService<IServer>().Features
            .Get<IServerAddressesFeature>()!.Addresses.Single();
        var webProject = Path.Combine(FindRepositoryRoot(), "src", "SentinelAI.Web");
        var webAssembly = Path.Combine(webProject, "bin", "Release", "net10.0", "SentinelAI.Web.dll");
        Assert.True(File.Exists(webAssembly), $"Expected the Release Web UI assembly at {webAssembly}.");

        var webUrl = $"http://127.0.0.1:{GetFreeTcpPort()}";
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = webProject,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        start.ArgumentList.Add(webAssembly);
        start.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
        start.Environment["DOTNET_ENVIRONMENT"] = "Development";
        start.Environment["ASPNETCORE_URLS"] = webUrl;
        start.Environment["Api__BaseUrl"] = apiUrl;
        start.Environment["Api__UseDevelopmentHeaders"] = "true";
        start.Environment["Dashboard__TenantId"] = tenantId.ToString();
        start.Environment["Dashboard__UserId"] = adminId.ToString();
        start.Environment["Dashboard__AnalystUserId"] = analystId.ToString();
        start.Environment["Dashboard__ViewerUserId"] = viewerId.ToString();
        start.Environment["Dashboard__ApproverUserId"] = Guid.NewGuid().ToString();

        using var webProcess = Process.Start(start);
        Assert.NotNull(webProcess);
        var standardOutput = webProcess!.StandardOutput.ReadToEndAsync();
        var standardError = webProcess.StandardError.ReadToEndAsync();

        try
        {
            await WaitForWebAsync(webProcess, webUrl, standardOutput, standardError);
            using var playwright = await Playwright.CreateAsync();
            await using var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions { Headless = true });

            // Analyst: opening a dossier must not call the provider. Only an explicit click may submit.
            var analystContext = await browser.NewContextAsync();
            var analystPage = await analystContext.NewPageAsync();
            await SignInAsync(analystPage, webUrl, "analyst");
            await OpenFirstFindingAsync(analystPage, webUrl);
            await analystPage.GetByText("Previously saved analysis visible to readers.", new PageGetByTextOptions { Exact = true })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });
            Assert.Equal(0, analysisCalls.GetValueOrDefault(findingId));
            await analystPage.GetByRole(AriaRole.Button,
                new PageGetByRoleOptions { NameRegex = new System.Text.RegularExpressions.Regex("Analyze with AI") }).ClickAsync();
            await analystPage.GetByText("Analysis saved. Review all recommendations and uncertainties; the source finding was not changed.",
                    new PageGetByTextOptions { Exact = true })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });
            await analystPage.GetByText("AI summary: provider call successful", new PageGetByTextOptions { Exact = true })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });
            Assert.Equal(1, analysisCalls.GetValueOrDefault(findingId));
            await analystContext.CloseAsync();

            // Provider failure is surfaced as a safe user-facing error; no source finding is changed.
            simulateProviderFailure = true;
            var failureContext = await browser.NewContextAsync();
            var failurePage = await failureContext.NewPageAsync();
            await SignInAsync(failurePage, webUrl, "analyst");
            await OpenFirstFindingAsync(failurePage, webUrl);
            await failurePage.GetByRole(AriaRole.Button,
                new PageGetByRoleOptions { NameRegex = new System.Text.RegularExpressions.Regex("Analyze with AI") }).ClickAsync();
            await failurePage.GetByRole(AriaRole.Alert)
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });
            Assert.Equal(2, analysisCalls.GetValueOrDefault(findingId)); // one successful and one failed request
            await failureContext.CloseAsync();
            simulateProviderFailure = false;

            // A finding with no persisted evidence is rejected by the API and shown to the operator.
            var noEvidenceContext = await browser.NewContextAsync();
            var noEvidencePage = await noEvidenceContext.NewPageAsync();
            await SignInAsync(noEvidencePage, webUrl, "analyst");
            await noEvidencePage.GotoAsync($"{webUrl}/findings", new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded });
            await noEvidencePage.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Inspect Evidence" }).Nth(1).ClickAsync();
            await noEvidencePage.GetByText("AI Security Analysis", new PageGetByTextOptions { Exact = true })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });
            await noEvidencePage.GetByRole(AriaRole.Button,
                new PageGetByRoleOptions { NameRegex = new System.Text.RegularExpressions.Regex("Analyze with AI") }).ClickAsync();
            await noEvidencePage.GetByRole(AriaRole.Alert)
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });
            Assert.Equal(1, analysisCalls.GetValueOrDefault(noEvidenceFindingId));
            await noEvidenceContext.CloseAsync();

            // No configured provider: show configuration guidance and disable the request control.
            providersConfigured = false;
            var unconfiguredContext = await browser.NewContextAsync();
            var unconfiguredPage = await unconfiguredContext.NewPageAsync();
            await SignInAsync(unconfiguredPage, webUrl, "analyst");
            await OpenFirstFindingAsync(unconfiguredPage, webUrl);
            await unconfiguredPage.GetByText("No AI provider is configured yet.", new PageGetByTextOptions { Exact = false })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });
            Assert.True(await unconfiguredPage.GetByRole(AriaRole.Button,
                new PageGetByRoleOptions { NameRegex = new System.Text.RegularExpressions.Regex("Analyze with AI") }).IsDisabledAsync());
            await unconfiguredContext.CloseAsync();

            // Administrator can also request analysis through the same operator-only UI.
            providersConfigured = true;
            var adminContext = await browser.NewContextAsync();
            var adminPage = await adminContext.NewPageAsync();
            await SignInAsync(adminPage, webUrl, "admin");
            await OpenFirstFindingAsync(adminPage, webUrl);
            await adminPage.GetByRole(AriaRole.Button,
                new PageGetByRoleOptions { NameRegex = new System.Text.RegularExpressions.Regex("Analyze with AI") }).ClickAsync();
            await adminPage.GetByText("Analysis saved. Review all recommendations and uncertainties; the source finding was not changed.",
                    new PageGetByTextOptions { Exact = true })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });
            Assert.Equal(3, analysisCalls.GetValueOrDefault(findingId)); // analyst success, provider failure, administrator success
            await adminContext.CloseAsync();

            // Viewer can read persisted analysis but cannot see or invoke the operator action.
            var providerStatusCallsBeforeViewer = Volatile.Read(ref providerStatusCalls);
            var viewerContext = await browser.NewContextAsync();
            var viewerPage = await viewerContext.NewPageAsync();
            await SignInAsync(viewerPage, webUrl, "viewer");
            await OpenFirstFindingAsync(viewerPage, webUrl);
            await viewerPage.GetByText("Previously saved analysis visible to readers.", new PageGetByTextOptions { Exact = true })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });
            Assert.Equal(providerStatusCallsBeforeViewer, Volatile.Read(ref providerStatusCalls));
            Assert.False(await viewerPage.GetByRole(AriaRole.Button,
                new PageGetByRoleOptions { NameRegex = new System.Text.RegularExpressions.Regex("Analyze with AI") }).IsVisibleAsync());
            Assert.Equal(3, analysisCalls.GetValueOrDefault(findingId));
            await viewerContext.CloseAsync();
        }
        finally
        {
            if (!webProcess.HasExited)
            {
                webProcess.Kill(entireProcessTree: true);
                await webProcess.WaitForExitAsync();
            }
            await api.StopAsync();
            await api.DisposeAsync();
        }
    }

    private static FindingAIAnalysisResponse CreateAnalysis(Guid findingId, DateTimeOffset createdAt)
        => new(Guid.NewGuid(), findingId, "ollama", "llama3.1", "finding-analysis-v1",
            new string('A', 64), new FindingAIAnalysisResultResponse("AI summary: provider call successful",
                "The stored evidence supports human review.", "High", [], ["The browser test uses a deterministic fixture."]),
            12, 24, "browser-response", "stop", createdAt);

    private static async Task SignInAsync(IPage page, string baseUrl, string role)
    {
        await page.GotoAsync($"{baseUrl}/auth/login?as={role}", new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded });
    }

    private static async Task OpenFirstFindingAsync(IPage page, string baseUrl)
    {
        await page.GotoAsync($"{baseUrl}/findings", new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded });
        await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Inspect Evidence" }).First.ClickAsync();
        await page.GetByText("AI Security Analysis", new PageGetByTextOptions { Exact = true })
            .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });
    }

    private static async Task WaitForWebAsync(Process process, string baseUrl, Task<string> stdout, Task<string> stderr)
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        for (var attempt = 0; attempt < 80; attempt++)
        {
            if (process.HasExited)
                throw new InvalidOperationException($"SentinelAI Web exited during startup.\nSTDOUT:\n{await stdout}\nSTDERR:\n{await stderr}");
            try
            {
                using var response = await client.GetAsync($"{baseUrl}/auth/login?choose=true");
                if (response.StatusCode == HttpStatusCode.OK) return;
            }
            catch (HttpRequestException) { }
            catch (TaskCanceledException) { }
            await Task.Delay(250);
        }

        throw new TimeoutException($"SentinelAI Web did not become ready.\nSTDOUT:\n{await stdout}\nSTDERR:\n{await stderr}");
    }

    private static string FindRepositoryRoot()
    {
        foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            var current = new DirectoryInfo(start);
            while (current is not null)
            {
                if (File.Exists(Path.Combine(current.FullName, "SentinelAI.slnx")))
                    return current.FullName;
                current = current.Parent;
            }
        }

        throw new DirectoryNotFoundException("Could not locate SentinelAI.slnx from the browser test working directory.");
    }

    private static int GetFreeTcpPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}
