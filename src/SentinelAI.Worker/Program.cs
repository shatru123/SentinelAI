using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using SentinelAI.Infrastructure;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using OpenTelemetry.Exporter;
using SentinelAI.Worker;

var builder = Host.CreateApplicationBuilder(args);
var isDevelopment = builder.Environment.IsDevelopment();
var clientCertificatePaths = WorkerCertificateConfigurationValidator.Validate(builder.Configuration, builder.Environment);

builder.Services.AddSingleton<WorkerOptions>();
builder.Services.AddSentinelInfrastructure(builder.Configuration, builder.Environment);
builder.Services.AddHttpClient<WorkerControlPlaneClient>((sp, client) =>
{
    var options = sp.GetRequiredService<WorkerOptions>();
    if (options.ControlPlaneUrl is not null) client.BaseAddress = new Uri(options.ControlPlaneUrl);
    if (isDevelopment)
    {
        var token = builder.Configuration["Worker:ControlPlaneToken"];
        if (!string.IsNullOrWhiteSpace(token))
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }
    client.DefaultRequestHeaders.Add("X-Worker-Id", options.Identity);
}).ConfigurePrimaryHttpMessageHandler(() =>
{
    var handler = new HttpClientHandler();
    if (!isDevelopment)
    {
        var password = builder.Configuration["Worker:ClientCertificatePassword"];
        foreach (var path in clientCertificatePaths)
        {
            var certificate = new X509Certificate2(path, password, X509KeyStorageFlags.EphemeralKeySet);
            if (!certificate.HasPrivateKey)
                throw new InvalidOperationException("Worker client certificate private key is not available.");
            handler.ClientCertificates.Add(certificate);
        }
    }
    return handler;
});
builder.Services.AddOpenTelemetry()
    .WithTracing(tracing => tracing.AddHttpClientInstrumentation().AddSource("SentinelAI.RabbitMq", "SentinelAI.Worker").AddOtlpExporter())
    .WithMetrics(metrics => metrics.AddMeter("SentinelAI.Jobs").AddOtlpExporter());
builder.Services.AddHostedService<Worker>();
builder.Services.AddHostedService<WorkerHeartbeatService>();
await builder.Build().RunAsync();
