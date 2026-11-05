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
if (!isDevelopment)
{
    // The standalone worker gets its own least-privilege database and broker principals.
    // These values are injected by the external secret manager, never committed to source.
    builder.Configuration["ConnectionStrings:SentinelAI"] = builder.Configuration["ConnectionStrings:SentinelAIWorker"];
    builder.Configuration["RabbitMQ:Username"] = builder.Configuration["RabbitMQ:WorkerUsername"];
    builder.Configuration["RabbitMQ:Password"] = builder.Configuration["RabbitMQ:WorkerPassword"];
}

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
            var certificate = X509CertificateLoader.LoadPkcs12FromFile(path, password, X509KeyStorageFlags.EphemeralKeySet);
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
