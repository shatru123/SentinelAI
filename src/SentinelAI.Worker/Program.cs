using SentinelAI.Infrastructure;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using OpenTelemetry.Exporter;
using SentinelAI.Worker;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddSingleton<WorkerOptions>();
builder.Services.AddSentinelInfrastructure(builder.Configuration, builder.Environment);
builder.Services.AddHttpClient<WorkerControlPlaneClient>((sp, client) =>
{
    var options = sp.GetRequiredService<WorkerOptions>();
    if (options.ControlPlaneUrl is not null) client.BaseAddress = new Uri(options.ControlPlaneUrl);
    var token = builder.Configuration["Worker:ControlPlaneToken"];
    if (!string.IsNullOrWhiteSpace(token)) client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
    client.DefaultRequestHeaders.Add("X-Worker-Id", options.Identity);
});
builder.Services.AddOpenTelemetry()
    .WithTracing(tracing => tracing.AddHttpClientInstrumentation().AddSource("SentinelAI.RabbitMq", "SentinelAI.Worker").AddOtlpExporter())
    .WithMetrics(metrics => metrics.AddMeter("SentinelAI.Jobs").AddOtlpExporter());
builder.Services.AddHostedService<Worker>();
builder.Services.AddHostedService<WorkerHeartbeatService>();
await builder.Build().RunAsync();
