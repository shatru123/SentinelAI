using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
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

public sealed class SchedulesBrowserAcceptanceTests
{
    [Fact]
    public async Task Browser_operator_can_create_control_review_and_acknowledge_scheduled_assessment()
    {
        // Chromium is provisioned by the repository CI workflow. Keep ordinary local dotnet test
        // runs independent of a browser install, while CI explicitly opts into this acceptance test.
        if (!string.Equals(Environment.GetEnvironmentVariable("SENTINELAI_RUN_BROWSER_TESTS"), "true", StringComparison.OrdinalIgnoreCase))
            return;

        var tenantId = Guid.NewGuid();
        var analystId = Guid.NewGuid();
        var scopeId = Guid.NewGuid();
        var scheduleId = Guid.NewGuid();
        var runId = Guid.NewGuid();
        var eventId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var scope = new ScopeResponse(scopeId, "Authorized browser test scope", tenantId,
            [new TargetDefinition(TargetKind.Web, "https://example.test/")],
            [WebAssessmentOperationProfiles.Passive], now.AddDays(7), true, WebHostingMode.Public);
        var schedules = new ConcurrentDictionary<Guid, AssessmentScheduleResponse>();
        var blockedScheduleId = Guid.NewGuid();
        schedules[blockedScheduleId] = new AssessmentScheduleResponse(blockedScheduleId, scopeId, analystId,
            WebAssessmentOperationProfiles.Passive, 24, now.AddDays(2), null, now.AddHours(-2),
            "Blocked", AssessmentScheduleStatus.Blocked,
            "The original public target authorization was revoked; review authorization and create a new schedule.",
            now.AddDays(-1));
        var runs = new ConcurrentDictionary<Guid, AssessmentScheduleRunResponse>();
        var driftEvents = new ConcurrentDictionary<Guid, AssessmentDriftEventResponse>();
        var notifications = new ConcurrentDictionary<Guid, AssessmentNotificationResponse>();

        var initialDrift = new AssessmentDriftEventResponse(eventId, scheduleId, runId,
            Guid.NewGuid(), Guid.NewGuid(), "NewFinding", new string('A', 64), null, FindingSeverity.High,
            "A finding with a new stable fingerprint was detected by the latest completed assessment.",
            now, null, null);
        driftEvents[eventId] = initialDrift;
        var notificationId = Guid.NewGuid();
        notifications[notificationId] = new AssessmentNotificationResponse(notificationId, eventId,
            "Scheduled assessment drift: NewFinding. Review the event in the SentinelAI Schedules workspace.", false, now);

        var apiBuilder = WebApplication.CreateBuilder();
        apiBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        var api = apiBuilder.Build();
        api.MapGet("/api/v1/auth/me", () => Results.Json(new CurrentUserResponse(
            "browser-analyst", tenantId, analystId, UserRole.SecurityAnalyst.ToString())));
        api.MapGet("/api/v1/scopes", () => Results.Json(new PagedResponse<ScopeResponse>([scope], 1, 100, 1)));
        api.MapGet("/api/v1/assessment-schedules", () => Results.Json(schedules.Values.OrderBy(x => x.CreatedAt).ToArray()));
        api.MapPost("/api/v1/assessment-schedules", (CreateAssessmentScheduleRequest request) =>
        {
            if (request.ScopeId != scopeId || request.OperationProfile != WebAssessmentOperationProfiles.Passive ||
                request.IntervalHours is < 24 or > 2160 || request.EndsAt >= scope.ExpiresAt)
                return Results.BadRequest();

            var created = new AssessmentScheduleResponse(Guid.NewGuid(), request.ScopeId, analystId,
                request.OperationProfile, request.IntervalHours, request.EndsAt, now.AddHours(request.IntervalHours),
                null, null, AssessmentScheduleStatus.Active, null, now);
            schedules.Clear();
            schedules[created.Id] = created;
            var createdRunId = Guid.NewGuid();
            runs[createdRunId] = new AssessmentScheduleRunResponse(createdRunId, created.Id,
                now.AddHours(-1), AssessmentScheduleRunStatus.Queued, Guid.NewGuid(), Guid.NewGuid(), null, now);
            return Results.Created($"/api/v1/assessment-schedules/{created.Id}", created);
        });
        api.MapGet("/api/v1/assessment-schedules/{id:guid}/runs", (Guid id) =>
            Results.Json(runs.Values.Where(x => x.ScheduleId == id).OrderByDescending(x => x.ScheduledFor).ToArray()));
        api.MapPost("/api/v1/assessment-schedules/{id:guid}/{action}", (Guid id, string action) =>
        {
            if (!schedules.TryGetValue(id, out var schedule)) return Results.NotFound();
            var status = action switch
            {
                "pause" => AssessmentScheduleStatus.Paused,
                "resume" => AssessmentScheduleStatus.Active,
                "disable" => AssessmentScheduleStatus.Disabled,
                _ => (AssessmentScheduleStatus?)null
            };
            if (status is null) return Results.BadRequest();
            schedules[id] = schedule with
            {
                Status = status.Value,
                NextRunAt = status == AssessmentScheduleStatus.Active ? now.AddDays(1) : null,
                LastResult = action
            };
            if (action == "resume")
                runs[runId] = new AssessmentScheduleRunResponse(runId, id, now, AssessmentScheduleRunStatus.Queued,
                    Guid.NewGuid(), Guid.NewGuid(), null, now);
            return Results.Ok(schedules[id]);
        });
        api.MapGet("/api/v1/assessment-drift-events", () => Results.Json(driftEvents.Values.OrderByDescending(x => x.CreatedAt).ToArray()));
        api.MapGet("/api/v1/notifications", () => Results.Json(notifications.Values.OrderByDescending(x => x.CreatedAt).ToArray()));
        api.MapPost("/api/v1/assessment-drift-events/{id:guid}/acknowledge", (Guid id) =>
        {
            if (!driftEvents.TryGetValue(id, out var drift)) return Results.NotFound();
            driftEvents[id] = drift with { AcknowledgedAt = DateTimeOffset.UtcNow, AcknowledgedBy = analystId };
            foreach (var pair in notifications.Where(x => x.Value.EventId == id).ToArray())
                notifications[pair.Key] = pair.Value with { IsRead = true };
            return Results.Ok();
        });

        await api.StartAsync();
        var apiUrl = api.Services.GetRequiredService<IServer>().Features
            .Get<IServerAddressesFeature>()!.Addresses.Single();
        var root = FindRepositoryRoot();
        var webProject = Path.Combine(root, "src", "SentinelAI.Web");
        var webAssembly = Path.Combine(webProject, "bin", "Release", "net10.0", "SentinelAI.Web.dll");
        Assert.True(File.Exists(webAssembly), $"Expected the Release Web UI assembly at {webAssembly}.");

        var webPort = GetFreeTcpPort();
        var webUrl = $"http://127.0.0.1:{webPort}";
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
        start.Environment["Dashboard__TenantId"] = tenantId.ToString();
        start.Environment["Dashboard__UserId"] = Guid.NewGuid().ToString();
        start.Environment["Dashboard__AnalystUserId"] = analystId.ToString();
        start.Environment["Dashboard__ViewerUserId"] = Guid.NewGuid().ToString();
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
            var page = await browser.NewPageAsync();
            await page.GotoAsync($"{webUrl}/auth/login?as=analyst", new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded });
            await page.GotoAsync($"{webUrl}/schedules", new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded });

            await page.GetByRole(AriaRole.Heading,
                new PageGetByRoleOptions { Name = "Create a reassessment schedule" })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 20_000 });
            await page.GetByText("The original public target authorization was revoked; review authorization and create a new schedule.",
                    new PageGetByTextOptions { Exact = true })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });

            await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Create schedule" }).ClickAsync();
            await page.GetByText("Schedule created.", new PageGetByTextOptions { Exact = false })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 15_000 });

            await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "History" }).ClickAsync();
            await page.GetByText("Execution history", new PageGetByTextOptions { Exact = true })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });
            await page.GetByText("Queued", new PageGetByTextOptions { Exact = true })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });

            await page.GetByText(initialDrift.Summary, new PageGetByTextOptions { Exact = true })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });
            await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Acknowledge" }).ClickAsync();
            await page.GetByText("Acknowledged ·", new PageGetByTextOptions { Exact = false })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });

            await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Pause" }).ClickAsync();
            await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Resume" })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });
            await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Resume" }).ClickAsync();
            await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Pause" })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });
            await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Disable" }).ClickAsync();
            await page.GetByText("Disabled", new PageGetByTextOptions { Exact = true })
                .WaitForAsync(new LocatorWaitForOptions { State = WaitForSelectorState.Visible, Timeout = 10_000 });

            Assert.Contains(schedules.Values, x => x.Status == AssessmentScheduleStatus.Disabled);
            Assert.True(notifications[notificationId].IsRead);
            Assert.NotNull(driftEvents[eventId].AcknowledgedAt);
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
