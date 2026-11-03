using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.JSInterop;
using SentinelAI.Web.Components.Shared;

namespace SentinelAI.UnitTests;

public sealed class DashboardComponentTests
{
    [Fact]
    public async Task MetricCard_maps_semantic_status_to_visible_accent()
    {
        await using var services = new ServiceCollection()
            .AddLogging()
            .BuildServiceProvider();

        await using var renderer = new HtmlRenderer(
            services,
            services.GetRequiredService<ILoggerFactory>());

        var parameters = ParameterView.FromDictionary(new Dictionary<string, object?>
        {
            [nameof(MetricCard.Title)] = "Critical Findings",
            [nameof(MetricCard.Value)] = "3",
            [nameof(MetricCard.StatusClass)] = "critical"
        });

        var html = await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var component = await renderer.RenderComponentAsync<MetricCard>(parameters);
            return component.ToHtmlString();
        });
        Assert.Contains("metric-card accent-red", html);
        Assert.Contains("Critical Findings", html);
        Assert.Contains(">3<", html);
    }

    [Fact]
    public async Task EmptyState_renders_navigation_action_when_ActionUrl_is_supplied()
    {
        await using var services = new ServiceCollection()
            .AddLogging()
            .BuildServiceProvider();

        await using var renderer = new HtmlRenderer(
            services,
            services.GetRequiredService<ILoggerFactory>());

        var parameters = ParameterView.FromDictionary(new Dictionary<string, object?>
        {
            [nameof(EmptyState.Title)] = "No Findings",
            [nameof(EmptyState.Message)] = "No findings have been recorded.",
            [nameof(EmptyState.ActionText)] = "Launch Assessment",
            [nameof(EmptyState.ActionUrl)] = "/web-assessments"
        });

        var html = await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var component = await renderer.RenderComponentAsync<EmptyState>(parameters);
            return component.ToHtmlString();
        });
        Assert.Contains("href=\"/web-assessments\"", html);
        Assert.Contains("Launch Assessment", html);
    }

    [Fact]
    public async Task CreatorProfile_renders_visible_creator_credit_and_profile_dialog()
    {
        await using var services = new ServiceCollection()
            .AddLogging()
            .AddSingleton<IJSRuntime, NoopJsRuntime>()
            .BuildServiceProvider();

        await using var renderer = new HtmlRenderer(
            services,
            services.GetRequiredService<ILoggerFactory>());

        var html = await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var component = await renderer.RenderComponentAsync<CreatorProfile>();
            return component.ToHtmlString();
        });

        Assert.Contains("Created by", html);
        Assert.Contains("Shatrughna Ambhore", html);
        Assert.Contains("modal-profile", html);
        Assert.Contains("aria-hidden", html);
    }

    private sealed class NoopJsRuntime : IJSRuntime
    {
        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args)
            => ValueTask.FromResult(default(TValue)!);

        public ValueTask<TValue> InvokeAsync<TValue>(
            string identifier,
            CancellationToken cancellationToken,
            object?[]? args)
            => ValueTask.FromResult(default(TValue)!);
    }
}
