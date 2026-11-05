using System.Security.Claims;
using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Components.Authorization;
using SentinelAI.Web;
using SentinelAI.Web.Components;

var builder = WebApplication.CreateBuilder(args);
WebProductionConfigurationValidator.Validate(builder.Configuration, builder.Environment);
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = builder.Configuration.GetValue<long>("Security:WebMaxRequestBodyBytes", 2 * 1024 * 1024);
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(builder.Configuration.GetValue("Security:RequestHeadersTimeoutSeconds", 15));
    options.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(builder.Configuration.GetValue("Security:KeepAliveTimeoutSeconds", 120));
});
builder.Services.AddRequestTimeouts(options =>
{
    options.DefaultPolicy = new Microsoft.AspNetCore.Http.Timeouts.RequestTimeoutPolicy
    {
        Timeout = TimeSpan.FromSeconds(builder.Configuration.GetValue("Security:WebRequestTimeoutSeconds", 60))
    };
});
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.ForwardLimit = 1;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
    foreach (var proxy in builder.Configuration.GetSection("ReverseProxy:KnownProxies").Get<string[]>() ?? [])
        if (IPAddress.TryParse(proxy, out var address)) options.KnownProxies.Add(address);
});
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = builder.Configuration.GetValue("RateLimiting:WebPermitLimit", 300),
                Window = TimeSpan.FromSeconds(builder.Configuration.GetValue("RateLimiting:WebWindowSeconds", 60)),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
});
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<SentinelApiClient>();
builder.Services.AddHttpClient("SentinelApi", client => client.BaseAddress = new Uri(builder.Configuration["Api:BaseUrl"] ?? "http://localhost:5109"))
    .ConfigureHttpClient(client => client.Timeout = TimeSpan.FromSeconds(30));
builder.Services.AddHttpClient("SentinelApiHealth", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["Api:HealthBaseUrl"] ??
        builder.Configuration["Api:BaseUrl"] ?? "http://localhost:5109");
    client.Timeout = TimeSpan.FromSeconds(5);
});
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "oidc";
}).AddCookie(options => { options.LoginPath = "/auth/login"; options.AccessDeniedPath = "/auth/denied"; options.SlidingExpiration = true; options.Cookie.HttpOnly = true; options.Cookie.SecurePolicy = CookieSecurePolicy.Always; options.Cookie.SameSite = SameSiteMode.Lax; });
var authority = builder.Configuration["Authentication:Authority"];
if (!string.IsNullOrWhiteSpace(authority))
{
    builder.Services.AddAuthentication().AddOpenIdConnect("oidc", options =>
    {
        options.Authority = authority;
        options.ClientId = builder.Configuration["Authentication:ClientId"] ?? "sentinelai-web";
        options.ClientSecret = builder.Configuration["Authentication:ClientSecret"];
        options.ResponseType = "code";
        options.UsePkce = true;
        options.SaveTokens = true;
        options.Events.OnTokenValidated = context =>
        {
            var accessToken = context.TokenEndpointResponse?.AccessToken;
            if (!string.IsNullOrWhiteSpace(accessToken) && context.Principal?.Identity is ClaimsIdentity identity)
            {
                identity.AddClaim(new Claim(SentinelApiAuthentication.AccessTokenClaim, accessToken));
            }

            return Task.CompletedTask;
        };
        options.Scope.Add("openid"); options.Scope.Add("profile"); options.Scope.Add("sentinelai-api");
    });
}
else
{
    builder.Services.AddAuthentication().AddPolicyScheme("oidc", null, options => options.ForwardDefault = CookieAuthenticationDefaults.AuthenticationScheme);
}
builder.Services.AddAuthorization();

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseForwardedHeaders();
app.UseRequestTimeouts();
app.Use(async (context, next) =>
{
    context.Response.Headers.TryAdd("X-Content-Type-Options", "nosniff");
    context.Response.Headers.TryAdd("X-Frame-Options", "DENY");
    context.Response.Headers.TryAdd("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.TryAdd("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    await next();
});
app.UseRateLimiter();
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.Use(async (context, next) =>
{
    if (!HttpMethods.IsGet(context.Request.Method) || !context.Request.Path.StartsWithSegments("/auth"))
    {
        await next(context);
        return;
    }

    var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
    if (context.Request.Path.Equals("/auth/login", StringComparison.OrdinalIgnoreCase))
    {
        if (!string.IsNullOrWhiteSpace(configuration["Authentication:Authority"]))
        {
            await Results.Challenge(new AuthenticationProperties { RedirectUri = "/" }, ["oidc"]).ExecuteAsync(context);
            return;
        }

        var environment = context.RequestServices.GetRequiredService<IHostEnvironment>();
        if (!environment.IsDevelopment())
        {
            await Results.Problem("Passwordless development login is available only in the Development environment.", statusCode: StatusCodes.Status404NotFound).ExecuteAsync(context);
            return;
        }

        if (string.Equals(context.Request.Query["choose"], "true", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.ContentType = "text/html; charset=utf-8";
            await context.Response.WriteAsync("""
                <!doctype html>
                <html lang="en">
                <head>
                  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
                  <title>SentinelAI · Development Sign In</title>
                  <style>
                    body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1220;color:#e8eef8;font:16px system-ui,sans-serif}
                    main{width:min(92vw,520px);padding:32px;border:1px solid #26354b;border-radius:18px;background:#121d2d}
                    h1{margin:0 0 8px}p{color:#aab8cc;line-height:1.5}
                    a{display:block;margin-top:14px;padding:15px 18px;border:1px solid #344862;border-radius:10px;color:#f5f8fc;text-decoration:none}
                    a:hover{background:#1b2d43}small{display:block;color:#91a1b7;margin-top:24px}
                  </style>
                </head>
                <body><main>
                  <h1>Sign in to SentinelAI</h1>
                  <p>Choose a local Development identity. These passwordless accounts are for local testing only.</p>
                  <a href="/auth/login?as=admin"><strong>Primary Admin</strong><br><span>development-admin · Full administration</span></a>
                  <a href="/auth/login?as=analyst"><strong>Security Analyst</strong><br><span>development-analyst · Operational access</span></a>
                  <a href="/auth/login?as=viewer"><strong>Read-only Viewer</strong><br><span>development-viewer · Read-only access</span></a>
                  <small>Development mode only. Configure real authentication before exposing SentinelAI to a network.</small>
                </main></body></html>
                """);
            return;
        }

        var tenant = configuration["Dashboard:TenantId"];
        var account = context.Request.Query["as"].ToString().Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(account)) account = "admin";

        string? user;
        string userName;
        string role;
        switch (account)
        {
            case "admin":
                user = configuration["Dashboard:UserId"];
                userName = configuration["Dashboard:UserName"] ?? "development-admin";
                role = "Admin";
                break;
            case "analyst":
                user = configuration["Dashboard:AnalystUserId"];
                userName = configuration["Dashboard:AnalystUserName"] ?? "development-analyst";
                role = "SecurityAnalyst";
                break;
            case "viewer":
                user = configuration["Dashboard:ViewerUserId"];
                userName = configuration["Dashboard:ViewerUserName"] ?? "development-viewer";
                role = "Viewer";
                break;
            default:
                await Results.Problem("Unknown Development account. Choose admin, analyst, or viewer.", statusCode: StatusCodes.Status400BadRequest).ExecuteAsync(context);
                return;
        }

        if (!Guid.TryParse(tenant, out _) || !Guid.TryParse(user, out _))
        {
            await Results.Problem("The selected Development identity is not configured.", statusCode: StatusCodes.Status503ServiceUnavailable).ExecuteAsync(context);
            return;
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user!),
            new Claim(ClaimTypes.Name, userName),
            new Claim("tenant_id", tenant!),
            new Claim(ClaimTypes.Role, role)
        };
        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)));
        context.Response.Redirect("/");
        return;
    }

    if (context.Request.Path.Equals("/auth/dev-approver", StringComparison.OrdinalIgnoreCase))
    {
        var environment = context.RequestServices.GetRequiredService<IHostEnvironment>();
        var tenant = configuration["Dashboard:TenantId"];
        var requester = configuration["Dashboard:UserId"];
        var approver = configuration["Dashboard:ApproverUserId"];
        if (!environment.IsDevelopment() || !string.IsNullOrWhiteSpace(configuration["Authentication:Authority"]))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        if (!Guid.TryParse(tenant, out _) || !Guid.TryParse(requester, out var requesterId) ||
            !Guid.TryParse(approver, out var approverId) || requesterId == approverId)
        {
            await Results.Problem("A distinct development approver identity is not configured.", statusCode: StatusCodes.Status503ServiceUnavailable).ExecuteAsync(context);
            return;
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, approver!),
            new Claim(ClaimTypes.Name, configuration["Dashboard:ApproverUserName"] ?? "development-approver"),
            new Claim("tenant_id", tenant!),
            new Claim(ClaimTypes.Role, "Admin")
        };
        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)));
        var returnUrl = context.Request.Query["returnUrl"].ToString();
        if (string.IsNullOrWhiteSpace(returnUrl) || !returnUrl.StartsWith("/", StringComparison.Ordinal) || returnUrl.StartsWith("//", StringComparison.Ordinal))
            returnUrl = "/";
        context.Response.Redirect(returnUrl);
        return;
    }

    if (context.Request.Path.Equals("/auth/logout", StringComparison.OrdinalIgnoreCase))
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        context.Response.Redirect("/auth/login?choose=true");
        return;
    }

    if (context.Request.Path.Equals("/auth/denied", StringComparison.OrdinalIgnoreCase))
    {
        await Results.Problem("You do not have access to this dashboard.", statusCode: StatusCodes.Status403Forbidden).ExecuteAsync(context);
        return;
    }

    await next(context);
});

app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
if (!builder.Environment.IsDevelopment() || builder.Configuration.GetValue("Web:EnableHttpsRedirection", false))
    app.UseWhen(context => !context.Request.Path.StartsWithSegments("/health"),
        branch => branch.UseHttpsRedirection());

app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

app.MapStaticAssets();
app.MapGet("/health/live", () => Results.Ok(new { status = "live", service = "sentinelai-web", utc = DateTimeOffset.UtcNow })).AllowAnonymous();
app.MapGet("/health/ready", async (IHttpClientFactory clients, CancellationToken cancellationToken) =>
{
    try
    {
        using var response = await clients.CreateClient("SentinelApiHealth").GetAsync("/health/ready", cancellationToken);
        if (!response.IsSuccessStatusCode)
            return Results.Json(new { status = "not-ready", dependency = "api", apiStatusCode = (int)response.StatusCode },
                statusCode: StatusCodes.Status503ServiceUnavailable);
        return Results.Ok(new { status = "ready", service = "sentinelai-web", api = "ready", utc = DateTimeOffset.UtcNow });
    }
    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
    catch
    {
        return Results.Json(new { status = "not-ready", dependency = "api" }, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
}).AllowAnonymous();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapGet("/downloads/vulnerability-intelligence-report", async (
    SentinelApiClient apiClient,
    CancellationToken cancellationToken) =>
{
    var content = await apiClient.GetBytesAsync("/api/v1/vulnerability-intelligence/report", cancellationToken);
    return Results.File(content, "text/csv; charset=utf-8",
        $"sentinelai-vulnerability-report-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}.csv");
}).RequireAuthorization();

app.Run();
