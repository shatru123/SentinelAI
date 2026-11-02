using System.Security.Claims;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.EntityFrameworkCore;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using OpenTelemetry.Exporter;
using SentinelAI.Application;
using SentinelAI.Api;
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
builder.Services.AddScoped<IPublicTargetAuthorizationService, PublicTargetAuthorizationService>();
builder.Services.AddOpenTelemetry()
    .WithTracing(tracing => tracing.AddAspNetCoreInstrumentation().AddHttpClientInstrumentation().AddSource("SentinelAI.RabbitMq", "SentinelAI.Worker").AddOtlpExporter())
    .WithMetrics(metrics => metrics.AddAspNetCoreInstrumentation().AddHttpClientInstrumentation().AddMeter("SentinelAI.Jobs").AddOtlpExporter());

if (builder.Environment.IsDevelopment())
    builder.Services.AddAuthentication(options => { options.DefaultAuthenticateScheme = "DevelopmentSmart"; options.DefaultChallengeScheme = "DevelopmentSmart"; })
        .AddPolicyScheme("DevelopmentSmart", null, options => options.ForwardDefaultSelector = context =>
            WorkerAuthenticationHandler.IsConfiguredWorkerToken(context.Request.Headers.Authorization.ToString(), builder.Configuration)
                ? "WorkerToken" : "DevelopmentHeaders")
        .AddScheme<AuthenticationSchemeOptions, SentinelAI.Api.DevelopmentAuthenticationHandler>("DevelopmentHeaders", _ => { })
        .AddScheme<AuthenticationSchemeOptions, SentinelAI.Api.WorkerAuthenticationHandler>("WorkerToken", _ => { });
else
    builder.Services.AddAuthentication(options => { options.DefaultAuthenticateScheme = "SmartBearer"; options.DefaultChallengeScheme = "SmartBearer"; })
        .AddPolicyScheme("SmartBearer", null, options => options.ForwardDefaultSelector = context =>
            WorkerAuthenticationHandler.IsConfiguredWorkerToken(context.Request.Headers.Authorization.ToString(), builder.Configuration)
                ? "WorkerToken" : JwtBearerDefaults.AuthenticationScheme)
        .AddScheme<AuthenticationSchemeOptions, SentinelAI.Api.WorkerAuthenticationHandler>("WorkerToken", _ => { })
        .AddJwtBearer(options =>
        {
            options.Authority = builder.Configuration["Authentication:Authority"];
            options.Audience = builder.Configuration["Authentication:Audience"] ?? "sentinelai-api";
            options.RequireHttpsMetadata = true;
        });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("Operator", policy => policy.RequireAuthenticatedUser().RequireRole(nameof(UserRole.Admin), nameof(UserRole.SecurityAnalyst)))
    .AddPolicy("Admin", policy => policy.RequireAuthenticatedUser().RequireRole(nameof(UserRole.Admin)))
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

api.MapPost("/public-target-authorizations", async (HttpContext context, PublicTargetAuthorizationRequest request, IPublicTargetAuthorizationService service, CancellationToken cancellationToken) =>
{
    var result = await service.RequestAsync(ToPrincipal(context), request, cancellationToken);
    return Results.Created($"/api/v1/public-target-authorizations/{result.Id}", result);
}).RequireAuthorization("Operator");

api.MapPost("/public-target-authorizations/{id:guid}/approve", async (HttpContext context, Guid id, PublicTargetAuthorizationApprovalRequest request, IPublicTargetAuthorizationService service, CancellationToken cancellationToken) =>
{
    var result = await service.ApproveAsync(ToPrincipal(context), id, request, cancellationToken);
    return result is null ? Results.NotFound() : Results.Ok(result);
}).RequireAuthorization("Admin");

api.MapPost("/public-target-authorizations/{id:guid}/revoke", async (HttpContext context, Guid id, IPublicTargetAuthorizationService service, CancellationToken cancellationToken) =>
    await service.RevokeAsync(ToPrincipal(context), id, cancellationToken) ? Results.NoContent() : Results.NotFound()).RequireAuthorization("Admin");

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

var workers = app.MapGroup("/api/v1/workers").RequireAuthorization("Worker");
workers.MapPost("/register", async (HttpContext context, WorkerRegistrationRequest request, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var principal = ToPrincipal(context);
    var identity = request.Identity.Trim();
    if (identity.Length is 0 or > 128 || request.Capabilities.Count is 0 or > 32 || !request.Capabilities.Contains("passive-mock", StringComparer.OrdinalIgnoreCase)) return Results.BadRequest("Invalid worker identity or capabilities.");
    if (!identity.Equals(context.User.FindFirstValue("worker_id"), StringComparison.Ordinal)) return Results.Unauthorized();
    var worker = await db.Workers.SingleOrDefaultAsync(x => x.TenantId == principal.TenantId && x.Identity == identity, cancellationToken);
    if (worker is null) { worker = new WorkerRegistration(principal.TenantId, identity, request.Version.Trim(), request.Capabilities); db.Workers.Add(worker); }
    if (worker.Status == WorkerStatus.Disabled) return Results.Forbid();
    worker.Heartbeat();
    await db.SaveChangesAsync(cancellationToken);
    return Results.Ok(ToWorkerResponse(worker));
});
workers.MapPost("/heartbeat", async (HttpContext context, WorkerHeartbeatRequest request, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var principal = ToPrincipal(context);
    if (!request.Identity.Trim().Equals(context.User.FindFirstValue("worker_id"), StringComparison.Ordinal)) return Results.Unauthorized();
    var worker = await db.Workers.SingleOrDefaultAsync(x => x.TenantId == principal.TenantId && x.Identity == request.Identity.Trim(), cancellationToken);
    if (worker is null) return Results.NotFound();
    worker.Heartbeat(); await db.SaveChangesAsync(cancellationToken);
    return Results.Ok(ToWorkerResponse(worker));
});

api.MapGet("/workers", async (HttpContext context, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    var workers = await db.Workers.AsNoTracking().Where(x => x.TenantId == tenantId).OrderBy(x => x.Identity).ToListAsync(cancellationToken);
    return Results.Ok(workers.Select(ToWorkerResponse));
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
static WorkerResponse ToWorkerResponse(WorkerRegistration worker) => new(worker.Id, worker.Identity, worker.Version, worker.Status, worker.Capabilities, worker.LastHeartbeatAt);
public partial class Program { }
