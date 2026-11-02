using System.Security.Claims;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.EntityFrameworkCore;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using SentinelAI.Application;
using SentinelAI.Contracts;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddProblemDetails();
builder.Services.ConfigureHttpJsonOptions(options => options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddOpenApi();
builder.Services.AddSentinelInfrastructure(builder.Configuration, builder.Environment);
builder.Services.AddScoped<IScopeService, ScopeService>();
builder.Services.AddScoped<IScanService, ScanService>();
builder.Services.AddOpenTelemetry().WithTracing(tracing => tracing.AddAspNetCoreInstrumentation().AddHttpClientInstrumentation())
    .WithMetrics(metrics => metrics.AddAspNetCoreInstrumentation().AddHttpClientInstrumentation());

if (builder.Environment.IsDevelopment() || builder.Configuration.GetValue<bool>("Authentication:UseDevelopmentHeaders"))
    builder.Services.AddAuthentication("DevelopmentHeaders").AddScheme<AuthenticationSchemeOptions, SentinelAI.Api.DevelopmentAuthenticationHandler>("DevelopmentHeaders", _ => { });
else
    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration["Authentication:Authority"];
        options.Audience = builder.Configuration["Authentication:Audience"] ?? "sentinelai-api";
        options.RequireHttpsMetadata = true;
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("Operator", policy => policy.RequireAuthenticatedUser().RequireRole(nameof(UserRole.Admin), nameof(UserRole.SecurityAnalyst)))
    .AddPolicy("Reader", policy => policy.RequireAuthenticatedUser().RequireRole(nameof(UserRole.Admin), nameof(UserRole.SecurityAnalyst), nameof(UserRole.Viewer)))
    .AddPolicy("Worker", policy => policy.RequireAuthenticatedUser().RequireRole(nameof(UserRole.Worker)));

var app = builder.Build();
if (builder.Configuration.GetValue<bool>("Database:ApplyMigrations"))
{
    await using var migrationScope = app.Services.CreateAsyncScope();
    await migrationScope.ServiceProvider.GetRequiredService<SentinelAI.Infrastructure.AppDbContext>().Database.MigrateAsync();
}
app.UseExceptionHandler(errorApp => errorApp.Run(async context =>
{
    var exception = context.Features.Get<IExceptionHandlerFeature>()?.Error;
    context.Response.ContentType = "application/problem+json";
    context.Response.StatusCode = exception switch
    {
        ScopeValidationException => StatusCodes.Status400BadRequest,
        BadHttpRequestException => StatusCodes.Status400BadRequest,
        KeyNotFoundException => StatusCodes.Status404NotFound,
        UnauthorizedAccessException => StatusCodes.Status403Forbidden,
        _ => StatusCodes.Status500InternalServerError
    };
    await Results.Problem(statusCode: context.Response.StatusCode, title: "Request could not be completed", detail: exception is ScopeValidationException scope ? string.Join(" ", scope.Errors) : null).ExecuteAsync(context);
}));
app.UseAuthentication();
app.UseAuthorization();
if (app.Environment.IsDevelopment()) app.MapOpenApi();
app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "sentinelai-api", utc = DateTimeOffset.UtcNow })).AllowAnonymous();
app.MapGet("/api/v1/auth/me", (HttpContext context) => Results.Ok(ToPrincipal(context).ToResponse())).RequireAuthorization();

var api = app.MapGroup("/api/v1").RequireAuthorization();
api.MapGet("/scopes", async (HttpContext context, IScopeService service, int page = 1, int pageSize = 25, CancellationToken cancellationToken = default) =>
{
    (page, pageSize) = NormalizePage(page, pageSize);
    return Results.Ok(await service.ListAsync(ToPrincipal(context), page, pageSize, cancellationToken));
}).RequireAuthorization("Reader");

api.MapPost("/scopes", async (HttpContext context, CreateScopeRequest request, IScopeService service, CancellationToken cancellationToken) =>
{
    var result = await service.CreateAsync(ToPrincipal(context), request, cancellationToken);
    return Results.Created($"/api/v1/scopes/{result.Id}", result);
}).RequireAuthorization("Operator");

api.MapPost("/scans", async (HttpContext context, CreateScanRequest request, IScanService service, CancellationToken cancellationToken) =>
{
    var result = await service.CreateAsync(ToPrincipal(context), request, cancellationToken);
    return Results.Accepted($"/api/v1/scans/{result.Id}", result);
}).RequireAuthorization("Operator");

api.MapGet("/scans/{id:guid}", async (HttpContext context, Guid id, IScanService service, CancellationToken cancellationToken) =>
{
    var result = await service.GetAsync(ToPrincipal(context), id, cancellationToken);
    return result is null ? Results.NotFound() : Results.Ok(result);
}).RequireAuthorization("Reader");

api.MapPost("/scans/{id:guid}/cancel", async (HttpContext context, Guid id, IScanService service, CancellationToken cancellationToken) =>
    await service.CancelAsync(ToPrincipal(context), id, cancellationToken) ? Results.NoContent() : Results.NotFound()).RequireAuthorization("Operator");

api.MapGet("/assets", async (HttpContext context, IAppDbContext db, int page = 1, int pageSize = 25, CancellationToken cancellationToken = default) =>
{
    (page, pageSize) = NormalizePage(page, pageSize);
    var tenantId = ToPrincipal(context).TenantId;
    var query = db.Assets.AsNoTracking().Where(x => x.TenantId == tenantId).OrderByDescending(x => x.LastSeenAt);
    var total = await query.CountAsync(cancellationToken);
    var assets = await query.Skip((page - 1) * pageSize).Take(pageSize).Select(x => new AssetResponse(x.Id, x.Address, x.Kind, x.IsOnline, x.LastSeenAt)).ToListAsync(cancellationToken);
    return Results.Ok(new PagedResponse<AssetResponse>(assets, page, pageSize, total));
}).RequireAuthorization("Reader");

api.MapGet("/findings", async (HttpContext context, IAppDbContext db, int page = 1, int pageSize = 25, CancellationToken cancellationToken = default) =>
{
    (page, pageSize) = NormalizePage(page, pageSize);
    var tenantId = ToPrincipal(context).TenantId;
    var query = db.Findings.AsNoTracking().Where(x => x.TenantId == tenantId).OrderByDescending(x => x.CreatedAt);
    var total = await query.CountAsync(cancellationToken);
    var findings = await query.Skip((page - 1) * pageSize).Take(pageSize).Select(x => new FindingResponse(x.Id, x.Title, x.Severity, x.AssetId, x.CreatedAt)).ToListAsync(cancellationToken);
    return Results.Ok(new PagedResponse<FindingResponse>(findings, page, pageSize, total));
}).RequireAuthorization("Reader");

api.MapGet("/agents", () => Results.Ok(Array.Empty<AgentResponse>())).RequireAuthorization("Reader");
api.MapGet("/ai/providers", (IConfiguration configuration) => Results.Ok(new { configured = configuration["AI:DefaultProvider"] ?? "none", providers = new[] { "openai", "anthropic", "ollama" } })).RequireAuthorization("Reader");
api.MapGet("/ai/health", (IConfiguration configuration) => Results.Ok(new { status = "advisory-only", defaultProvider = configuration["AI:DefaultProvider"] ?? "none" })).RequireAuthorization("Reader");
api.MapGet("/monitoring/health", () => Results.Ok(new { status = "healthy", activeProbing = false })).RequireAuthorization("Reader");
api.MapGet("/monitoring/events", async (HttpContext context, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    return Results.Ok(await db.AuditEvents.AsNoTracking().Where(x => x.TenantId == tenantId).OrderByDescending(x => x.OccurredAt).Take(100).ToListAsync(cancellationToken));
}).RequireAuthorization("Reader");

app.Run();

static PrincipalContext ToPrincipal(HttpContext context)
{
    var user = context.User;
    if (!Guid.TryParse(user.FindFirstValue("tenant_id"), out var tenantId) || !Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
        throw new UnauthorizedAccessException("Tenant and user claims are required.");
    var role = Enum.TryParse<UserRole>(user.FindFirstValue(ClaimTypes.Role), true, out var parsed) ? parsed : UserRole.Viewer;
    return new PrincipalContext(tenantId, userId, user.FindFirstValue(ClaimTypes.Name) ?? userId.ToString(), role);
}

static (int Page, int PageSize) NormalizePage(int page, int pageSize) => (Math.Max(1, page), Math.Clamp(pageSize, 1, 100));

public partial class Program { }
