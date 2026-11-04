using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Components.Authorization;
using SentinelAI.Web;
using SentinelAI.Web.Components;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<SentinelApiClient>();
builder.Services.AddHttpClient("SentinelApi", client => client.BaseAddress = new Uri(builder.Configuration["Api:BaseUrl"] ?? "http://localhost:5109"))
    .ConfigureHttpClient(client => client.Timeout = TimeSpan.FromSeconds(30));
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "oidc";
}).AddCookie(options => { options.LoginPath = "/auth/login"; options.AccessDeniedPath = "/auth/denied"; options.SlidingExpiration = true; });
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

        var tenant = configuration["Dashboard:TenantId"];
        var user = configuration["Dashboard:UserId"];
        if (!Guid.TryParse(tenant, out _) || !Guid.TryParse(user, out _))
        {
            await Results.Problem("Dashboard development identity is not configured.", statusCode: StatusCodes.Status503ServiceUnavailable).ExecuteAsync(context);
            return;
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user!),
            new Claim(ClaimTypes.Name, configuration["Dashboard:UserName"] ?? "operator"),
            new Claim("tenant_id", tenant!),
            new Claim(ClaimTypes.Role, configuration["Dashboard:Role"] ?? "SecurityAnalyst")
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
        context.Response.Redirect("/auth/login");
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
if (builder.Configuration.GetValue("Web:EnableHttpsRedirection", !builder.Environment.IsDevelopment())) app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

app.MapStaticAssets();
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
