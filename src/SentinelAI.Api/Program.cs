using System.Text.Json;
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
using SentinelAI.Agent.Vulnerability;
using SentinelAI.Contracts;
using SentinelAI.Domain;
using SentinelAI.Infrastructure;
using SentinelAI.Security.Policy;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddProblemDetails();
builder.Services.ConfigureHttpJsonOptions(options => options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddOpenApi();
builder.Services.AddSentinelInfrastructure(builder.Configuration, builder.Environment);
builder.Services.AddScoped<IScopeService, ScopeService>();
builder.Services.AddScoped<IScanService, ScanService>();
builder.Services.AddScoped<IPublicTargetAuthorizationService, PublicTargetAuthorizationService>();
builder.Services.AddScoped<IWebAssessmentService, WebAssessmentService>();
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
api.MapGet("/dashboard/summary", async (HttpContext context, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    var assetsObserved = await db.Assets.AsNoTracking().Where(x => x.TenantId == tenantId).CountAsync(cancellationToken);
    var reachabilityConfirmed = await db.Assets.AsNoTracking().Where(x => x.TenantId == tenantId && x.LastSuccessfulReachabilityAt != null).CountAsync(cancellationToken);
    var observedServices = await db.AssetServices.AsNoTracking().Where(x => x.TenantId == tenantId).CountAsync(cancellationToken);

    var totalFindings = await db.Findings.AsNoTracking().Where(x => x.TenantId == tenantId).CountAsync(cancellationToken);
    var criticalFindings = await db.Findings.AsNoTracking().Where(x => x.TenantId == tenantId && x.Severity == FindingSeverity.Critical).CountAsync(cancellationToken);
    var highFindings = await db.Findings.AsNoTracking().Where(x => x.TenantId == tenantId && x.Severity == FindingSeverity.High).CountAsync(cancellationToken);
    var mediumFindings = await db.Findings.AsNoTracking().Where(x => x.TenantId == tenantId && x.Severity == FindingSeverity.Medium).CountAsync(cancellationToken);
    var lowFindings = await db.Findings.AsNoTracking().Where(x => x.TenantId == tenantId && x.Severity == FindingSeverity.Low).CountAsync(cancellationToken);
    var infoFindings = await db.Findings.AsNoTracking().Where(x => x.TenantId == tenantId && x.Severity == FindingSeverity.Informational).CountAsync(cancellationToken);

    var activeAssessments = await db.WebAssessments.AsNoTracking().Where(x => x.TenantId == tenantId && (x.Status == WebAssessmentStatus.Running || x.Status == WebAssessmentStatus.Queued)).CountAsync(cancellationToken);
    var runningJobs = await db.AgentJobs.AsNoTracking().Where(x => x.TenantId == tenantId && x.Status == ScanJobStatus.Running).CountAsync(cancellationToken);
    var queuedJobs = await db.AgentJobs.AsNoTracking().Where(x => x.TenantId == tenantId && x.Status == ScanJobStatus.Queued).CountAsync(cancellationToken);
    var completedJobs = await db.AgentJobs.AsNoTracking().Where(x => x.TenantId == tenantId && x.Status == ScanJobStatus.Completed).CountAsync(cancellationToken);
    var totalJobs = await db.AgentJobs.AsNoTracking().Where(x => x.TenantId == tenantId).CountAsync(cancellationToken);

    var healthyWorkers = await db.Workers.AsNoTracking().Where(x => x.TenantId == tenantId && x.Status == WorkerStatus.Healthy).CountAsync(cancellationToken);
    var totalWorkers = await db.Workers.AsNoTracking().Where(x => x.TenantId == tenantId).CountAsync(cancellationToken);

    var recentAssessments = await db.WebAssessments.AsNoTracking()
        .Where(x => x.TenantId == tenantId)
        .OrderByDescending(x => x.CreatedAt)
        .Take(5)
        .Join(db.AgentJobs.AsNoTracking().Where(x => x.TenantId == tenantId),
            x => x.AgentJobId,
            x => x.Id,
            (assessment, job) => new WebAssessmentResponse(
                assessment.Id, assessment.AgentJobId, assessment.ScopeId, assessment.TargetUrl,
                assessment.Profile, assessment.HostingMode, assessment.Status, job.Status,
                assessment.CreatedAt, assessment.StartedAt, assessment.CompletedAt,
                assessment.DiscoveredEndpointCount, assessment.ReportStorageKey))
        .ToListAsync(cancellationToken);

    var recentScans = await db.AgentJobs.AsNoTracking()
        .Where(x => x.TenantId == tenantId)
        .OrderByDescending(x => x.CreatedAt)
        .Take(5)
        .Join(db.TargetScopes.AsNoTracking().Where(x => x.TenantId == tenantId),
            job => job.ScopeId,
            scope => scope.Id,
            (job, scope) => new ScanJobSummaryResponse(
                job.Id, job.ScopeId, scope.Name, job.OperationProfile, job.Status,
                job.CreatedAt, job.StartedAt, job.CompletedAt, job.AssignedWorkerIdentity, job.ExpiresAt, job.FailureReason))
        .ToListAsync(cancellationToken);

    var recentEvents = await db.AuditEvents.AsNoTracking()
        .Where(x => x.TenantId == tenantId)
        .OrderByDescending(x => x.OccurredAt)
        .Take(5)
        .Select(x => new MonitoringEventResponse(x.Id, x.TenantId, x.Action, x.ResourceType, x.ResourceId, x.ActorId, x.OccurredAt, x.Detail))
        .ToListAsync(cancellationToken);

    return Results.Ok(new DashboardSummaryResponse(
        assetsObserved, reachabilityConfirmed, observedServices,
        totalFindings, criticalFindings, highFindings, mediumFindings, lowFindings, infoFindings,
        activeAssessments, runningJobs, totalJobs, healthyWorkers, totalWorkers,
        recentAssessments, recentScans, recentEvents, queuedJobs, completedJobs));
}).RequireAuthorization("Reader");
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

api.MapGet("/public-target-authorizations", async (HttpContext context, IPublicTargetAuthorizationService service, CancellationToken cancellationToken) =>
    Results.Ok(await service.ListAsync(ToPrincipal(context), cancellationToken))).RequireAuthorization("Reader");

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

api.MapPost("/web-assessments", async (HttpContext context, CreateWebAssessmentRequest request, IWebAssessmentService service, CancellationToken cancellationToken) =>
{
    var result = await service.CreateAsync(ToPrincipal(context), request, cancellationToken);
    return Results.Accepted($"/api/v1/web-assessments/{result.Id}", result);
}).RequireAuthorization("Operator");

api.MapGet("/web-assessments/{id:guid}", async (HttpContext context, Guid id, IWebAssessmentService service, CancellationToken cancellationToken) =>
{
    var result = await service.GetAsync(ToPrincipal(context), id, cancellationToken);
    return result is null ? Results.NotFound() : Results.Ok(result);
}).RequireAuthorization("Reader");

api.MapGet("/web-assessments", async (HttpContext context, IAppDbContext db, int page = 1, int pageSize = 25, string? status = null, string? search = null, CancellationToken cancellationToken = default) =>
{
    (page, pageSize) = NormalizePage(page, pageSize);
    var tenantId = ToPrincipal(context).TenantId;
    var query = db.WebAssessments.AsNoTracking().Where(x => x.TenantId == tenantId);

    if (!string.IsNullOrWhiteSpace(status) && Enum.TryParse<WebAssessmentStatus>(status, true, out var parsedStatus))
    {
        query = query.Where(x => x.Status == parsedStatus);
    }

    if (!string.IsNullOrWhiteSpace(search))
    {
        var term = search.Trim();
        query = query.Where(x => x.TargetUrl.Contains(term) || x.Profile.Contains(term));
    }

    var total = await query.CountAsync(cancellationToken);
    var items = await query.OrderByDescending(x => x.CreatedAt)
        .Skip((page - 1) * pageSize)
        .Take(pageSize)
        .Join(db.AgentJobs.AsNoTracking().Where(x => x.TenantId == tenantId),
            assessment => assessment.AgentJobId,
            job => job.Id,
            (assessment, job) => new WebAssessmentResponse(
                assessment.Id, assessment.AgentJobId, assessment.ScopeId, assessment.TargetUrl,
                assessment.Profile, assessment.HostingMode, assessment.Status, job.Status,
                assessment.CreatedAt, assessment.StartedAt, assessment.CompletedAt,
                assessment.DiscoveredEndpointCount, assessment.ReportStorageKey))
        .ToListAsync(cancellationToken);

    return Results.Ok(new PagedResponse<WebAssessmentResponse>(items, page, pageSize, total));
}).RequireAuthorization("Reader");

api.MapGet("/web-assessments/{id:guid}/endpoints", async (HttpContext context, Guid id, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    var assessment = await db.WebAssessments.AsNoTracking().AnyAsync(x => x.Id == id && x.TenantId == tenantId, cancellationToken);
    if (!assessment) return Results.NotFound();
    var endpoints = await db.WebAssessmentEndpoints.AsNoTracking().Where(x => x.AssessmentId == id && x.TenantId == tenantId).OrderBy(x => x.Url).Select(x => new WebAssessmentEndpointResponse(x.Id, x.Url, x.Method, x.Depth, x.Kind, x.DiscoveredAt)).ToListAsync(cancellationToken);
    return Results.Ok(endpoints);
}).RequireAuthorization("Reader");

api.MapGet("/web-assessments/{id:guid}/findings", async (HttpContext context, Guid id, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    if (!await db.WebAssessments.AsNoTracking().AnyAsync(x => x.Id == id && x.TenantId == tenantId, cancellationToken)) return Results.NotFound();
    var findings = await db.Findings.AsNoTracking().Where(x => x.TenantId == tenantId && x.AssessmentId == id).OrderByDescending(x => x.CreatedAt)
        .Select(x => new WebAssessmentFindingResponse(x.Id, x.Title, x.Severity, x.Category, x.Confidence, x.AffectedUrl, x.HttpMethod, x.Parameter, x.Description, x.Impact, x.Reproduction, x.Remediation, x.CheckStatus, x.CreatedAt)).ToListAsync(cancellationToken);
    return Results.Ok(findings);
}).RequireAuthorization("Reader");

api.MapGet("/web-assessments/{id:guid}/checks", async (HttpContext context, Guid id, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    if (!await db.WebAssessments.AsNoTracking().AnyAsync(x => x.Id == id && x.TenantId == tenantId, cancellationToken)) return Results.NotFound();
    var checks = await db.WebAssessmentChecks.AsNoTracking().Where(x => x.AssessmentId == id && x.TenantId == tenantId).OrderBy(x => x.CheckId).ThenBy(x => x.AffectedEndpoint)
        .Select(x => new WebAssessmentCheckResponse(x.Id, x.CheckId, x.Name, x.Category, x.Status, x.StartedAt, x.CompletedAt, x.AffectedEndpoint, x.Reason)).ToListAsync(cancellationToken);
    return Results.Ok(checks);
}).RequireAuthorization("Reader");

api.MapPost("/web-assessments/{id:guid}/cancel", async (HttpContext context, Guid id, IAppDbContext db, IScanService scans, CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    var jobId = await db.WebAssessments.AsNoTracking().Where(x => x.Id == id && x.TenantId == tenantId).Select(x => (Guid?)x.AgentJobId).SingleOrDefaultAsync(cancellationToken);
    return jobId is null ? Results.NotFound() : await scans.CancelAsync(ToPrincipal(context), jobId.Value, cancellationToken) ? Results.NoContent() : Results.NotFound();
}).RequireAuthorization("Operator");

api.MapGet("/web-assessments/{id:guid}/screenshots", async (HttpContext context, Guid id, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    if (!await db.WebAssessments.AsNoTracking().AnyAsync(x => x.Id == id && x.TenantId == tenantId, cancellationToken)) return Results.NotFound();
    var screenshots = await db.AssessmentScreenshots.AsNoTracking().Where(x => x.AssessmentId == id && x.TenantId == tenantId).OrderBy(x => x.CapturedAt).Select(x => new ScreenshotResponse(x.Id, x.Url, x.ScreenshotType, x.Format, x.Sha256, x.CapturedAt)).ToListAsync(cancellationToken);
    return Results.Ok(screenshots);
}).RequireAuthorization("Reader");

api.MapGet("/web-assessments/{id:guid}/screenshots/{screenshotId:guid}", async (HttpContext context, Guid id, Guid screenshotId, IAppDbContext db, IAssessmentArtifactStore artifacts, CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    var screenshot = await db.AssessmentScreenshots.AsNoTracking().SingleOrDefaultAsync(x => x.Id == screenshotId && x.AssessmentId == id && x.TenantId == tenantId, cancellationToken);
    if (screenshot is null) return Results.NotFound();
    var content = await artifacts.GetAsync(tenantId, screenshot.StorageKey, cancellationToken);
    return content is null ? Results.NotFound() : Results.File(content, screenshot.Format, $"sentinelai-{screenshot.Id:N}.png");
}).RequireAuthorization("Reader");

api.MapGet("/web-assessments/{id:guid}/findings/{findingId:guid}/evidence", async (HttpContext context, Guid id, Guid findingId, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    var finding = await db.Findings.AsNoTracking().SingleOrDefaultAsync(x => x.Id == findingId && x.AssessmentId == id && x.TenantId == tenantId, cancellationToken);
    if (finding is null) return Results.NotFound();
    var evidence = await db.Evidence.AsNoTracking().Where(x => x.FindingId == findingId && x.TenantId == tenantId).OrderBy(x => x.CollectedAt).Select(x => new EvidenceResponse(x.Id, x.FindingId, x.Source, x.Summary, x.Sha256, x.RedactedContent, x.ContentType, x.CollectedAt)).ToListAsync(cancellationToken);
    return Results.Ok(evidence);
}).RequireAuthorization("Reader");

api.MapGet("/web-assessments/{id:guid}/report", async (HttpContext context, Guid id, IAppDbContext db, IAssessmentArtifactStore artifacts, CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    var assessment = await db.WebAssessments.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id && x.TenantId == tenantId, cancellationToken);
    if (assessment is null || assessment.Status != WebAssessmentStatus.Completed || string.IsNullOrWhiteSpace(assessment.ReportStorageKey)) return Results.NotFound();
    var content = await artifacts.GetPublishedReportAsync(tenantId, assessment.Id, assessment.ReportStorageKey, cancellationToken);
    return content is null ? Results.NotFound() : Results.File(content, "text/html; charset=utf-8", $"sentinelai-{assessment.Id:N}.html");
}).RequireAuthorization("Reader");

api.MapGet("/scans", async (HttpContext context, IAppDbContext db, int page = 1, int pageSize = 25, string? status = null, string? search = null, CancellationToken cancellationToken = default) =>
{
    (page, pageSize) = NormalizePage(page, pageSize);
    var tenantId = ToPrincipal(context).TenantId;
    var query = db.AgentJobs.AsNoTracking().Where(x => x.TenantId == tenantId);

    if (!string.IsNullOrWhiteSpace(status) && Enum.TryParse<ScanJobStatus>(status, true, out var parsedStatus))
    {
        query = query.Where(x => x.Status == parsedStatus);
    }

    if (!string.IsNullOrWhiteSpace(search))
    {
        var term = search.Trim();
        if (Guid.TryParse(term, out var jobOrScopeId))
        {
            query = query.Where(x => x.Id == jobOrScopeId || x.ScopeId == jobOrScopeId);
        }
        else
        {
            var normalizedTerm = term.ToLowerInvariant();
            var matchingScopeIds = db.TargetScopes.AsNoTracking()
                .Where(x => x.TenantId == tenantId && x.Name.ToLower().Contains(normalizedTerm))
                .Select(x => x.Id);
            query = query.Where(x =>
                matchingScopeIds.Contains(x.ScopeId)
                || x.OperationProfile.ToLower().Contains(normalizedTerm)
                || (x.AssignedWorkerIdentity != null && x.AssignedWorkerIdentity.ToLower().Contains(normalizedTerm)));
        }
    }

    var total = await query.CountAsync(cancellationToken);
    var jobs = await query.OrderByDescending(x => x.CreatedAt)
        .Skip((page - 1) * pageSize)
        .Take(pageSize)
        .Join(db.TargetScopes.AsNoTracking().Where(x => x.TenantId == tenantId),
            job => job.ScopeId,
            scope => scope.Id,
            (job, scope) => new ScanJobSummaryResponse(
                job.Id, job.ScopeId, scope.Name, job.OperationProfile, job.Status,
                job.CreatedAt, job.StartedAt, job.CompletedAt, job.AssignedWorkerIdentity, job.ExpiresAt, job.FailureReason))
        .ToListAsync(cancellationToken);

    return Results.Ok(new PagedResponse<ScanJobSummaryResponse>(jobs, page, pageSize, total));
}).RequireAuthorization("Reader");

api.MapGet("/scans/{id:guid}", async (HttpContext context, Guid id, IScanService service, CancellationToken cancellationToken) =>
{
    var result = await service.GetAsync(ToPrincipal(context), id, cancellationToken);
    return result is null ? Results.NotFound() : Results.Ok(result);
}).RequireAuthorization("Reader");

api.MapPost("/scans/{id:guid}/cancel", async (HttpContext context, Guid id, IScanService service, CancellationToken cancellationToken) =>
    await service.CancelAsync(ToPrincipal(context), id, cancellationToken) ? Results.NoContent() : Results.NotFound()).RequireAuthorization("Operator");

api.MapGet("/assets", async (HttpContext context, IAppDbContext db, int page = 1, int pageSize = 25, string? search = null, string? kind = null, string? status = null, CancellationToken cancellationToken = default) =>
{
    (page, pageSize) = NormalizePage(page, pageSize);
    var tenantId = ToPrincipal(context).TenantId;
    var query = db.Assets.AsNoTracking().Where(x => x.TenantId == tenantId);
    if (!string.IsNullOrWhiteSpace(search))
    {
        var term = search.Trim();
        query = query.Where(x => x.Address.Contains(term));
    }
    if (!string.IsNullOrWhiteSpace(kind) && !string.Equals(kind, "All", StringComparison.OrdinalIgnoreCase))
    {
        if (Enum.TryParse<TargetKind>(kind, true, out var targetKind))
        {
            query = query.Where(x => x.Kind == targetKind);
        }
    }
    if (string.Equals(status, "Online", StringComparison.OrdinalIgnoreCase))
    {
        query = query.Where(x => x.LastSuccessfulReachabilityAt != null);
    }
    else if (string.Equals(status, "Unconfirmed", StringComparison.OrdinalIgnoreCase))
    {
        query = query.Where(x => x.LastSuccessfulReachabilityAt == null);
    }
    query = query.OrderByDescending(x => x.LastObservedAt);
    var total = await query.CountAsync(cancellationToken);
    var assets = await query.Skip((page - 1) * pageSize).Take(pageSize).Select(x => new AssetResponse(x.Id, x.Address, x.Kind, x.IsOnline, x.LastObservedAt, x.LastSuccessfulReachabilityAt)).ToListAsync(cancellationToken);
    return Results.Ok(new PagedResponse<AssetResponse>(assets, page, pageSize, total));
}).RequireAuthorization("Reader");

api.MapGet("/findings", async (HttpContext context, IAppDbContext db, int page = 1, int pageSize = 25, string? severity = null, string? search = null, CancellationToken cancellationToken = default) =>
{
    (page, pageSize) = NormalizePage(page, pageSize);
    var tenantId = ToPrincipal(context).TenantId;
    var query = db.Findings.AsNoTracking().Where(x => x.TenantId == tenantId);
    if (!string.IsNullOrWhiteSpace(severity) && !string.Equals(severity, "All", StringComparison.OrdinalIgnoreCase))
    {
        if (Enum.TryParse<FindingSeverity>(severity, true, out var sev))
        {
            query = query.Where(x => x.Severity == sev);
        }
    }
    if (!string.IsNullOrWhiteSpace(search))
    {
        var term = search.Trim();
        query = query.Where(x => x.Title.Contains(term) || (x.AffectedUrl != null && x.AffectedUrl.Contains(term)));
    }
    query = query.OrderByDescending(x => x.CreatedAt);
    var total = await query.CountAsync(cancellationToken);
    var findings = await query.Skip((page - 1) * pageSize).Take(pageSize).Select(x => new FindingResponse(x.Id, x.Title, x.Severity, x.AssetId, x.CreatedAt)).ToListAsync(cancellationToken);
    return Results.Ok(new PagedResponse<FindingResponse>(findings, page, pageSize, total));
}).RequireAuthorization("Reader");

api.MapGet("/findings/{id:guid}", async (HttpContext context, Guid id, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    var finding = await db.Findings.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id && x.TenantId == tenantId, cancellationToken);
    if (finding is null) return Results.NotFound();

    string? targetUrl = null;
    if (finding.AssessmentId is not null)
    {
        targetUrl = await db.WebAssessments.AsNoTracking()
            .Where(x => x.Id == finding.AssessmentId && x.TenantId == tenantId)
            .Select(x => x.TargetUrl)
            .SingleOrDefaultAsync(cancellationToken);
    }

    var evidence = await db.Evidence.AsNoTracking()
        .Where(x => x.FindingId == id && x.TenantId == tenantId)
        .OrderBy(x => x.CollectedAt)
        .Select(x => new EvidenceResponse(x.Id, x.FindingId, x.Source, x.Summary, x.Sha256, x.RedactedContent, x.ContentType, x.CollectedAt))
        .ToListAsync(cancellationToken);

    var screenshots = new List<ScreenshotResponse>();
    if (finding.AssessmentId is not null)
    {
        screenshots = await db.AssessmentScreenshots.AsNoTracking()
            .Where(x => x.AssessmentId == finding.AssessmentId && x.TenantId == tenantId && (x.FindingId == id || x.FindingId == null))
            .OrderBy(x => x.CapturedAt)
            .Select(x => new ScreenshotResponse(x.Id, x.Url, x.ScreenshotType, x.Format, x.Sha256, x.CapturedAt))
            .ToListAsync(cancellationToken);
    }

    return Results.Ok(new FindingDetailResponse(
        finding.Id, finding.Title, finding.Severity, finding.AssetId, finding.AssessmentId,
        targetUrl, finding.Category, finding.Confidence, finding.AffectedUrl, finding.HttpMethod,
        finding.Parameter, finding.Description, finding.Impact, finding.Reproduction, finding.Remediation,
        finding.CheckStatus, finding.CreatedAt, evidence, screenshots));
}).RequireAuthorization("Reader");

api.MapGet("/assets/{id:guid}/services", async (HttpContext context, Guid id, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    var assetExists = await db.Assets.AsNoTracking().AnyAsync(x => x.Id == id && x.TenantId == tenantId, cancellationToken);
    if (!assetExists) return Results.NotFound();
    var services = await db.AssetServices.AsNoTracking().Where(x => x.AssetId == id && x.TenantId == tenantId).OrderBy(x => x.Port).ThenBy(x => x.Protocol)
        .Select(x => new AssetServiceResponse(x.Id, x.AssetId, x.Protocol, x.Port, x.Name, x.Version, x.ObservedAt)).ToListAsync(cancellationToken);
    return Results.Ok(services);
}).RequireAuthorization("Reader");

api.MapGet("/agents", () => Results.Ok(Array.Empty<AgentResponse>())).RequireAuthorization("Reader");
api.MapGet("/ai/providers", (IConfiguration configuration) =>
{
    var selectedProvider = (configuration["AI:DefaultProvider"] ?? configuration["AI_PROVIDER"] ?? "none").Trim().ToLowerInvariant();
    return Results.Ok(new
    {
        selectedProvider,
        openAiCredentialsConfigured = !string.IsNullOrWhiteSpace(configuration["OPENAI_API_KEY"] ?? configuration["AI:OpenAI:ApiKey"]),
        anthropicCredentialsConfigured = !string.IsNullOrWhiteSpace(configuration["ANTHROPIC_API_KEY"] ?? configuration["AI:Anthropic:ApiKey"]),
        ollamaEndpointConfigured = !string.IsNullOrWhiteSpace(configuration["OLLAMA_BASE_URL"] ?? configuration["AI:Ollama:Endpoint"]),
        connectivityVerified = false,
        inferenceImplemented = false,
        executionMode = "advisory-only"
    });
}).RequireAuthorization("Reader");
api.MapGet("/ai/health", (IConfiguration configuration) => Results.Ok(new
{
    status = "advisory-only",
    defaultProvider = configuration["AI:DefaultProvider"] ?? configuration["AI_PROVIDER"] ?? "none",
    connectivityVerified = false,
    inferenceImplemented = false
})).RequireAuthorization("Reader");
api.MapGet("/monitoring/health", async (
    AppDbContext db,
    IScanJobQueue queue,
    IServiceProvider services,
    IConfiguration configuration,
    CancellationToken cancellationToken) =>
{
    var databaseConnected = false;
    try { databaseConnected = await db.Database.CanConnectAsync(cancellationToken); }
    catch { databaseConnected = false; }

    var messagingStatus = "unavailable";
    if (queue is InMemoryScanJobQueue)
    {
        messagingStatus = "configured-in-memory";
    }
    else if (queue is RabbitMqScanJobQueue)
    {
        var rabbit = services.GetService<RabbitMqConnectionProvider>();
        if (rabbit is not null)
        {
            try
            {
                var connection = await rabbit.GetConnectionAsync(cancellationToken);
                messagingStatus = connection.IsOpen ? "connected" : "unavailable";
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch { messagingStatus = "unavailable"; }
        }
    }

    var engineRegistered = services.GetService<IWebAssessmentEngine>() is not null
        && services.GetService<IScreenshotCaptureService>() is not null;
    var engineStatus = engineRegistered ? "registered" : "not-registered";
    var inProcessWorkerRegistered = queue is InMemoryScanJobQueue
        && configuration.GetValue<bool>("Worker:RunInProcess");
    var messagingReady = messagingStatus is "connected" or "configured-in-memory";
    var overallStatus = databaseConnected && messagingReady && engineRegistered ? "healthy" : "degraded";

    return Results.Ok(new
    {
        status = overallStatus,
        databaseStatus = databaseConnected ? "connected" : "unavailable",
        messagingStatus,
        assessmentEngineStatus = engineStatus,
        workerExecutionMode = inProcessWorkerRegistered ? "in-process" : "external",
        configuredWorkerIdentity = configuration["Worker:Identity"] ?? "compose-worker",
        activeProbing = false,
        checkedAt = DateTimeOffset.UtcNow
    });
}).RequireAuthorization("Reader");
api.MapGet("/monitoring/events", async (HttpContext context, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    return Results.Ok(await db.AuditEvents.AsNoTracking().Where(x => x.TenantId == tenantId).OrderByDescending(x => x.OccurredAt).Take(100).ToListAsync(cancellationToken));
}).RequireAuthorization("Reader");

var workers = app.MapGroup("/api/v1/workers").RequireAuthorization("Worker");
workers.MapPost("/register", async (HttpContext context, WorkerRegistrationRequest request, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var principal = ToPrincipal(context);
    var identity = request.Identity?.Trim() ?? string.Empty;
    var requestedCapabilities = request.Capabilities?.Select(capability => capability?.Trim()).ToArray() ?? [];
    if (identity.Length is 0 or > 128 || string.IsNullOrWhiteSpace(request.Version) || requestedCapabilities.Length is 0 or > 32 || requestedCapabilities.Any(string.IsNullOrWhiteSpace) || request.Capacity is < 1 or > 256 || !requestedCapabilities.Any(capability => capability!.Equals("passive-mock", StringComparison.OrdinalIgnoreCase) || capability.Equals("passive-inventory", StringComparison.OrdinalIgnoreCase) || capability.Equals("web-assessment", StringComparison.OrdinalIgnoreCase) || capability.Equals("private-web-assessment", StringComparison.OrdinalIgnoreCase))) return Results.BadRequest("Invalid worker identity, version, capacity or capabilities.");
    if (!identity.Equals(context.User.FindFirstValue("worker_id"), StringComparison.Ordinal)) return Results.Unauthorized();
    var worker = await db.Workers.SingleOrDefaultAsync(x => x.TenantId == principal.TenantId && x.Identity == identity, cancellationToken);
    if (worker is null) return Results.NotFound();
    if (worker.Status == WorkerStatus.Disabled) return Results.Forbid();
    if (requestedCapabilities.Any(capability => !worker.Capabilities.Contains(capability!, StringComparer.OrdinalIgnoreCase)))
        return Results.Forbid();
    worker.Heartbeat(0, request.Capacity);
    await db.SaveChangesAsync(cancellationToken);
    return Results.Ok(ToWorkerResponse(worker));
});
api.MapPost("/workers/{identity}/private-authorization", async (HttpContext context, string identity, PrivateWorkerAuthorizationRequest request, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var principal = ToPrincipal(context);
    if (principal.Role != UserRole.Admin) return Results.Forbid();
    if (string.IsNullOrWhiteSpace(identity) || request.NetworkRanges is null || request.NetworkRanges.Count > 64 || (request.Enabled && request.NetworkRanges.Count < 1) || request.NetworkRanges.Any(range => !TargetScopeValidator.IsValidPrivateNetworkRange(range)))
        return Results.BadRequest("Only valid private IPv4/IPv6 CIDR ranges may be approved.");
    var worker = await db.Workers.SingleOrDefaultAsync(x => x.TenantId == principal.TenantId && x.Identity == identity.Trim(), cancellationToken);
    if (worker is null) return Results.NotFound();
    if (request.Enabled && !worker.Capabilities.Contains("web-assessment", StringComparer.OrdinalIgnoreCase))
        return Results.BadRequest("Private authorization requires the web-assessment capability.");
    await using var transaction = await db.BeginTransactionAsync(cancellationToken);
    if (request.Enabled) worker.ConfigurePrivateAssessmentAuthorization(request.NetworkRanges);
    else worker.RevokePrivateAssessmentAuthorization();
    db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, request.Enabled ? "worker.private-authorization.approved" : "worker.private-authorization.revoked", nameof(WorkerRegistration), worker.Id, "Administrator-controlled private web assessment authorization changed."));
    await db.SaveChangesAsync(cancellationToken);
    await transaction.CommitAsync(cancellationToken);
    return Results.Ok(ToWorkerResponse(worker));
}).RequireAuthorization("Admin");
workers.MapPost("/heartbeat", async (HttpContext context, WorkerHeartbeatRequest request, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var principal = ToPrincipal(context);
    if (!request.Identity.Trim().Equals(context.User.FindFirstValue("worker_id"), StringComparison.Ordinal)) return Results.Unauthorized();
    var worker = await db.Workers.SingleOrDefaultAsync(x => x.TenantId == principal.TenantId && x.Identity == request.Identity.Trim(), cancellationToken);
    if (worker is null) return Results.NotFound();
    if (request.ActiveJobs < 0 || request.ActiveJobs > request.Capacity || request.Capacity > 256) return Results.BadRequest("Invalid worker heartbeat capacity.");
    worker.Heartbeat(request.ActiveJobs, request.Capacity, request.LastJobStartedAt, request.LastJobCompletedAt); await db.SaveChangesAsync(cancellationToken);
    return Results.Ok(ToWorkerResponse(worker));
});

api.MapGet("/workers", async (HttpContext context, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    var workers = await db.Workers.Where(x => x.TenantId == tenantId).OrderBy(x => x.Identity).ToListAsync(cancellationToken);
    var now = DateTimeOffset.UtcNow;
    var staleAfter = TimeSpan.FromSeconds(Math.Clamp(context.RequestServices.GetRequiredService<IConfiguration>().GetValue("Worker:HeartbeatStaleSeconds", 45), 15, 3600));
    foreach (var worker in workers) if (worker.IsStale(now, staleAfter)) worker.MarkUnhealthy();
    if (workers.Any(x => x.Status == WorkerStatus.Unhealthy)) await db.SaveChangesAsync(cancellationToken);
    return Results.Ok(workers.Select(ToWorkerResponse));
}).RequireAuthorization("Reader");

api.MapPost("/workers/{identity}/provision", async (HttpContext context, string identity, WorkerProvisionRequest request, IAppDbContext db, CancellationToken cancellationToken) =>
{
    var principal = ToPrincipal(context);
    if (principal.Role != UserRole.Admin) return Results.Forbid();
    var normalizedIdentity = identity.Trim();
    var capabilities = request.Capabilities?.Select(x => x.Trim()).Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray() ?? [];
    var allowedCapabilities = new[] { "passive-mock", "passive-inventory", "web-assessment", "private-web-assessment", "cancellation", "scope-validation", "bounded-concurrency" };
    if (normalizedIdentity.Length is 0 or > 128 || string.IsNullOrWhiteSpace(request.Version) || capabilities.Length == 0 || capabilities.Any(capability => !allowedCapabilities.Contains(capability, StringComparer.OrdinalIgnoreCase))) return Results.BadRequest("Invalid worker provisioning request.");
    var ranges = request.PrivateNetworkRanges?.Select(x => x.Trim()).Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray() ?? [];
    if (capabilities.Contains("private-web-assessment", StringComparer.OrdinalIgnoreCase) && (!capabilities.Contains("web-assessment", StringComparer.OrdinalIgnoreCase) || ranges.Length == 0 || ranges.Any(range => !TargetScopeValidator.IsValidPrivateNetworkRange(range)))) return Results.BadRequest("Private web capability requires web-assessment and approved private IPv4/IPv6 CIDR ranges.");
    if (!capabilities.Contains("private-web-assessment", StringComparer.OrdinalIgnoreCase) && ranges.Length > 0) return Results.BadRequest("Private network ranges require private-web-assessment capability.");
    await using var transaction = await db.BeginTransactionAsync(cancellationToken);
    var worker = await db.Workers.SingleOrDefaultAsync(x => x.TenantId == principal.TenantId && x.Identity == normalizedIdentity, cancellationToken);
    if (worker is null) { worker = new WorkerRegistration(principal.TenantId, normalizedIdentity, request.Version.Trim(), []); db.Workers.Add(worker); }
    worker.ProvisionByAdministrator(request.Version, capabilities, ranges);
    await db.SaveChangesAsync(cancellationToken);
    db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, worker.Capabilities.Contains("private-web-assessment", StringComparer.OrdinalIgnoreCase) ? "worker.provisioned.private" : "worker.provisioned", nameof(WorkerRegistration), worker.Id, "Administrator provisioned worker capabilities and private network authorization."));
    db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "worker.capabilities.changed", nameof(WorkerRegistration), worker.Id, "Administrator-controlled worker capabilities replaced atomically."));
    await db.SaveChangesAsync(cancellationToken);
    await transaction.CommitAsync(cancellationToken);
    return Results.Ok(ToWorkerResponse(worker));
}).RequireAuthorization("Admin");



api.MapPost("/vulnerability-intelligence/cves/{cveId}/sync", async (
    HttpContext context,
    string cveId,
    VulnerabilityIntelligenceSyncService sync,
    IAppDbContext db,
    CancellationToken cancellationToken) =>
{
    if (!CveId.TryParse(cveId, out var parsed)) return Results.BadRequest("A valid CVE identifier is required.");
    var principal = ToPrincipal(context);
    var processed = await sync.SyncCveAsync(parsed, cancellationToken);
    db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "vulnerability-intelligence.cve.synced",
        nameof(VulnerabilityCatalogEntry), null, $"NVD CVE sync completed for {parsed.Value}; records processed: {processed}."));
    await db.SaveChangesAsync(cancellationToken);
    return Results.Ok(new { cveId = parsed.Value, recordsProcessed = processed });
}).RequireAuthorization("Admin");

api.MapPost("/vulnerability-intelligence/kev/sync", async (
    HttpContext context,
    VulnerabilityIntelligenceSyncService sync,
    IAppDbContext db,
    CancellationToken cancellationToken) =>
{
    var principal = ToPrincipal(context);
    var processed = await sync.SyncKevAsync(cancellationToken);
    db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "vulnerability-intelligence.kev.synced",
        "CisaKevCatalog", null, $"CISA KEV catalog sync completed; entries processed: {processed}."));
    await db.SaveChangesAsync(cancellationToken);
    return Results.Ok(new { recordsProcessed = processed });
}).RequireAuthorization("Admin");

api.MapPost("/vulnerability-intelligence/epss/sync", async (
    HttpContext context,
    SyncEpssRequest request,
    VulnerabilityIntelligenceSyncService sync,
    IAppDbContext db,
    CancellationToken cancellationToken) =>
{
    if (request.CveIds is null || request.CveIds.Count is < 1 or > 50)
        return Results.BadRequest("Provide between 1 and 50 CVE identifiers.");
    var ids = new List<CveId>();
    foreach (var value in request.CveIds)
    {
        if (!CveId.TryParse(value, out var parsed)) return Results.BadRequest($"Invalid CVE identifier: {value}");
        ids.Add(parsed);
    }
    var uniqueIds = ids.Distinct().ToArray();
    var knownIds = await db.VulnerabilityCatalogEntries.AsNoTracking()
        .Where(entry => uniqueIds.Select(id => id.Value).Contains(entry.CveId))
        .Select(entry => entry.CveId)
        .ToListAsync(cancellationToken);
    if (knownIds.Count != uniqueIds.Length)
        return Results.BadRequest("EPSS enrichment is limited to CVEs already present in the local catalog.");

    var principal = ToPrincipal(context);
    var processed = await sync.SyncEpssAsync(uniqueIds, cancellationToken);
    db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "vulnerability-intelligence.epss.synced",
        "FirstEpssFeed", null, $"FIRST EPSS lookup completed; entries processed: {processed}."));
    await db.SaveChangesAsync(cancellationToken);
    return Results.Ok(new { recordsProcessed = processed });
}).RequireAuthorization("Admin");

api.MapGet("/vulnerability-intelligence/cves", async (
    string? search,
    int limit,
    IAppDbContext db,
    CancellationToken cancellationToken) =>
{
    limit = Math.Clamp(limit == 0 ? 25 : limit, 1, 100);
    var query = db.VulnerabilityCatalogEntries.AsNoTracking();
    if (!string.IsNullOrWhiteSpace(search))
    {
        var term = search.Trim();
        if (term.Length > 128) return Results.BadRequest("Search term is too long.");
        query = query.Where(entry => entry.CveId.Contains(term) || entry.Description.Contains(term));
    }
    var entries = await query.OrderByDescending(entry => entry.LastModifiedAt).Take(limit)
        .Select(entry => new { entry.CveId, entry.Status, entry.PublishedAt, entry.LastModifiedAt, entry.Description })
        .ToListAsync(cancellationToken);
    return Results.Ok(entries);
}).RequireAuthorization("Reader");

api.MapGet("/vulnerability-intelligence/cves/{cveId}", async (
    string cveId,
    IAppDbContext db,
    CancellationToken cancellationToken) =>
{
    if (!CveId.TryParse(cveId, out var parsed)) return Results.BadRequest("A valid CVE identifier is required.");
    var entry = await db.VulnerabilityCatalogEntries.AsNoTracking().SingleOrDefaultAsync(x => x.CveId == parsed.Value, cancellationToken);
    if (entry is null) return Results.NotFound();

    var metrics = await db.VulnerabilityCvssMetrics.AsNoTracking().Where(x => x.CveId == parsed.Value)
        .OrderBy(x => x.Version).ThenBy(x => x.Source)
        .Select(x => new VulnerabilityCvssResponse(x.Version, x.Vector, x.BaseScore, x.Severity, x.Source, x.ObservedAt))
        .ToListAsync(cancellationToken);
    var epss = await db.VulnerabilityEpssScores.AsNoTracking().Where(x => x.CveId == parsed.Value)
        .OrderByDescending(x => x.AsOfDate)
        .Select(x => new VulnerabilityEpssResponse(x.Score, x.Percentile, x.AsOfDate, x.ImportedAt))
        .FirstOrDefaultAsync(cancellationToken);
    var kev = await db.VulnerabilityKevEntries.AsNoTracking().Where(x => x.CveId == parsed.Value && x.IsListed)
        .Select(x => new VulnerabilityKevResponse(x.IsListed, x.CatalogVersion, x.CatalogReleasedAt,
            x.VendorProject, x.Product, x.DateAdded, x.DueDate, x.RequiredAction, x.KnownRansomwareCampaignUse))
        .FirstOrDefaultAsync(cancellationToken);

    var response = new VulnerabilityCatalogResponse(entry.CveId, entry.Status, entry.PublishedAt, entry.LastModifiedAt,
        entry.Description, JsonSerializer.Deserialize<string[]>(entry.CweIdsJson) ?? [],
        JsonSerializer.Deserialize<string[]>(entry.ReferencesJson) ?? [], metrics, epss, kev);
    return Results.Ok(response);
}).RequireAuthorization("Reader");

api.MapPost("/assets/{assetId:guid}/software-components", async (
    HttpContext context,
    Guid assetId,
    CreateSoftwareComponentRequest request,
    IAppDbContext db,
    CancellationToken cancellationToken) =>
{
    var principal = ToPrincipal(context);
    if (!await db.Assets.AnyAsync(x => x.Id == assetId && x.TenantId == principal.TenantId, cancellationToken))
        return Results.NotFound();

    if (!Cpe23Name.TryParse(request.CpeName, out var cpe)
        || !string.Equals(cpe!.Vendor, request.Vendor.Trim(), StringComparison.OrdinalIgnoreCase)
        || !string.Equals(cpe.Product, request.Product.Trim(), StringComparison.OrdinalIgnoreCase))
        return Results.BadRequest("CPE vendor and product must match the supplied product identity.");

    var hasInventoryEvidence = await db.AssetServices.AnyAsync(x =>
        x.Id == request.EvidenceId && x.AssetId == assetId && x.TenantId == principal.TenantId, cancellationToken);
    var hasFindingEvidence = await (from evidence in db.Evidence
                                     join finding in db.Findings on evidence.FindingId equals finding.Id
                                     where evidence.Id == request.EvidenceId && evidence.TenantId == principal.TenantId
                                         && finding.TenantId == principal.TenantId && finding.AssetId == assetId
                                     select evidence.Id).AnyAsync(cancellationToken);
    if (request.EvidenceId == Guid.Empty || (!hasInventoryEvidence && !hasFindingEvidence))
        return Results.BadRequest("Evidence must be an inventory service observation or an asset finding belonging to this tenant and asset.");

    var component = new SoftwareComponent(principal.TenantId, assetId, request.Vendor, request.Product,
        request.Version, cpe.Value, request.IdentificationMethod, request.EvidenceId, request.Confidence);
    db.SoftwareComponents.Add(component);
    db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "software-component.candidate.created",
        nameof(SoftwareComponent), component.Id, "An evidence-linked software identity candidate was recorded; it is not operator-confirmed."));
    await db.SaveChangesAsync(cancellationToken);
    return Results.Created($"/api/v1/software-components/{component.Id}",
        new SoftwareComponentResponse(component.Id, component.AssetId, component.Vendor, component.Product, component.Version,
            component.CpeName, component.IdentificationMethod, component.EvidenceId, component.Confidence,
            component.IsOperatorConfirmed, component.FirstObservedAt, component.LastObservedAt));
}).RequireAuthorization("Operator");

api.MapGet("/assets/{assetId:guid}/software-components", async (
    HttpContext context,
    Guid assetId,
    IAppDbContext db,
    CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    if (!await db.Assets.AnyAsync(x => x.Id == assetId && x.TenantId == tenantId, cancellationToken)) return Results.NotFound();
    var components = await db.SoftwareComponents.AsNoTracking().Where(x => x.TenantId == tenantId && x.AssetId == assetId)
        .OrderBy(x => x.Vendor).ThenBy(x => x.Product)
        .Select(x => new SoftwareComponentResponse(x.Id, x.AssetId, x.Vendor, x.Product, x.Version, x.CpeName,
            x.IdentificationMethod, x.EvidenceId, x.Confidence, x.IsOperatorConfirmed, x.FirstObservedAt, x.LastObservedAt))
        .ToListAsync(cancellationToken);
    return Results.Ok(components);
}).RequireAuthorization("Reader");

api.MapPost("/software-components/{componentId:guid}/confirm", async (
    HttpContext context,
    Guid componentId,
    ConfirmSoftwareComponentRequest request,
    IAppDbContext db,
    CancellationToken cancellationToken) =>
{
    var principal = ToPrincipal(context);
    var component = await db.SoftwareComponents.SingleOrDefaultAsync(
        x => x.Id == componentId && x.TenantId == principal.TenantId, cancellationToken);
    if (component is null) return Results.NotFound();

    var hasInventoryEvidence = await db.AssetServices.AnyAsync(x =>
        x.Id == request.EvidenceId && x.AssetId == component.AssetId && x.TenantId == principal.TenantId, cancellationToken);
    var hasFindingEvidence = await (from evidence in db.Evidence
                                    join finding in db.Findings on evidence.FindingId equals finding.Id
                                    where evidence.Id == request.EvidenceId && evidence.TenantId == principal.TenantId
                                        && finding.TenantId == principal.TenantId && finding.AssetId == component.AssetId
                                    select evidence.Id).AnyAsync(cancellationToken);
    if (request.EvidenceId == Guid.Empty || (!hasInventoryEvidence && !hasFindingEvidence))
        return Results.BadRequest("Confirmation requires evidence belonging to this tenant and asset.");

    component.Confirm(request.EvidenceId, request.Confidence);
    db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "software-component.identity.confirmed",
        nameof(SoftwareComponent), component.Id, "An operator confirmed the product identity using asset-linked evidence."));
    await db.SaveChangesAsync(cancellationToken);
    return Results.Ok(new SoftwareComponentResponse(component.Id, component.AssetId, component.Vendor, component.Product,
        component.Version, component.CpeName, component.IdentificationMethod, component.EvidenceId, component.Confidence,
        component.IsOperatorConfirmed, component.FirstObservedAt, component.LastObservedAt));
}).RequireAuthorization("Operator");

api.MapPost("/software-components/{componentId:guid}/evaluate/{cveId}", async (
    HttpContext context,
    Guid componentId,
    string cveId,
    IAppDbContext db,
    CancellationToken cancellationToken) =>
{
    if (!CveId.TryParse(cveId, out var parsed)) return Results.BadRequest("A valid CVE identifier is required.");
    var principal = ToPrincipal(context);
    var component = await db.SoftwareComponents.AsNoTracking().SingleOrDefaultAsync(
        x => x.Id == componentId && x.TenantId == principal.TenantId, cancellationToken);
    if (component is null) return Results.NotFound();

    var catalog = await db.VulnerabilityCatalogEntries.AsNoTracking().SingleOrDefaultAsync(
        x => x.CveId == parsed.Value, cancellationToken);
    if (catalog is null) return Results.NotFound("CVE is not in the local catalog.");

    ApplicabilityNode applicability;
    try
    {
        applicability = catalog.Status.Equals("Rejected", StringComparison.OrdinalIgnoreCase)
            || catalog.Status.Equals("Withdrawn", StringComparison.OrdinalIgnoreCase)
            ? new UnsupportedApplicabilityNode("The source marks this CVE as rejected or withdrawn.")
            : catalog.ApplicabilityJson is null
                ? new UnsupportedApplicabilityNode("The CVE has no applicability configuration.")
                : NvdApplicabilityParser.Parse(catalog.ApplicabilityJson);
    }
    catch (JsonException)
    {
        applicability = new UnsupportedApplicabilityNode("The stored applicability payload is invalid.");
    }

    var identity = new ProductIdentity(Cpe23Name.Parse(component.CpeName), component.Version,
        component.IsOperatorConfirmed, component.EvidenceId.ToString());
    var evaluation = CveAssetMatcher.Evaluate(applicability, identity);
    var status = evaluation.Status switch
    {
        CveAssetMatchStatus.Confirmed => VulnerabilityMatchStatus.Confirmed,
        CveAssetMatchStatus.Potential => VulnerabilityMatchStatus.Potential,
        CveAssetMatchStatus.NotAffected => VulnerabilityMatchStatus.NotAffected,
        _ => VulnerabilityMatchStatus.Inconclusive
    };
    var existing = await db.AssetVulnerabilityMatches.SingleOrDefaultAsync(x =>
        x.TenantId == principal.TenantId && x.SoftwareComponentId == component.Id && x.CveId == parsed.Value,
        cancellationToken);
    if (existing is null)
    {
        existing = new AssetVulnerabilityMatch(principal.TenantId, component.AssetId, component.Id,
            parsed.Value, status, evaluation.Explanation, FindFirstCriteriaId(applicability));
        db.AssetVulnerabilityMatches.Add(existing);
    }
    else
    {
        existing.Update(status, evaluation.Explanation, FindFirstCriteriaId(applicability));
    }

    db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "vulnerability.match.evaluated",
        nameof(AssetVulnerabilityMatch), existing.Id, $"CVE {parsed.Value} evaluated with status {status}."));
    await db.SaveChangesAsync(cancellationToken);
    return Results.Ok(new AssetVulnerabilityMatchResponse(existing.Id, existing.AssetId, existing.SoftwareComponentId,
        existing.CveId, existing.Status, existing.Explanation, existing.CriteriaId, existing.FirstObservedAt, existing.LastObservedAt));
}).RequireAuthorization("Operator");

api.MapGet("/vulnerability-intelligence/matches", async (
    HttpContext context,
    string? status,
    int limit,
    IAppDbContext db,
    CancellationToken cancellationToken) =>
{
    var tenantId = ToPrincipal(context).TenantId;
    limit = Math.Clamp(limit == 0 ? 100 : limit, 1, 500);
    var query = db.AssetVulnerabilityMatches.AsNoTracking().Where(x => x.TenantId == tenantId);
    if (!string.IsNullOrWhiteSpace(status) && Enum.TryParse<VulnerabilityMatchStatus>(status, true, out var parsedStatus))
        query = query.Where(x => x.Status == parsedStatus);
    var matches = await query.OrderByDescending(x => x.LastObservedAt).Take(limit)
        .Select(x => new AssetVulnerabilityMatchResponse(x.Id, x.AssetId, x.SoftwareComponentId, x.CveId,
            x.Status, x.Explanation, x.CriteriaId, x.FirstObservedAt, x.LastObservedAt))
        .ToListAsync(cancellationToken);
    return Results.Ok(matches);
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

static string? FindFirstCriteriaId(ApplicabilityNode node) => node switch
{
    CpeMatchNode match when !string.IsNullOrWhiteSpace(match.CriteriaId) => match.CriteriaId,
    LogicalApplicabilityNode logical => logical.Children
        .Select(FindFirstCriteriaId)
        .FirstOrDefault(criteriaId => !string.IsNullOrWhiteSpace(criteriaId)),
    _ => null
};
static WorkerResponse ToWorkerResponse(WorkerRegistration worker) => new(worker.Id, worker.Identity, worker.Version, worker.Status, worker.Capabilities, worker.LastHeartbeatAt, worker.CurrentActiveJobs, worker.MaximumCapacity, worker.LastJobStartedAt, worker.LastJobCompletedAt, worker.PrivateAssessmentApproved, worker.ApprovedPrivateNetworkRanges);
public partial class Program { }
