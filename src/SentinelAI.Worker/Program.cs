using SentinelAI.Infrastructure;
using SentinelAI.Worker;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddSentinelInfrastructure(builder.Configuration, builder.Environment);
builder.Services.AddHostedService<Worker>();
await builder.Build().RunAsync();
