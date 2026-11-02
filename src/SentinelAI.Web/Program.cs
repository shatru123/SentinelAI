using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Components.Authorization;
using SentinelAI.Web;
using SentinelAI.Web.Components;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuthenticatedApiHandler>();
builder.Services.AddHttpClient("SentinelApi", client => client.BaseAddress = new Uri(builder.Configuration["Api:BaseUrl"] ?? "http://localhost:5080"))
    .AddHttpMessageHandler<AuthenticatedApiHandler>();
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
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
if (builder.Configuration.GetValue("Web:EnableHttpsRedirection", !builder.Environment.IsDevelopment())) app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/auth/login", async (HttpContext context, IConfiguration configuration) =>
{
    if (!string.IsNullOrWhiteSpace(configuration["Authentication:Authority"])) return Results.Challenge(new AuthenticationProperties { RedirectUri = "/" }, ["oidc"]);
    var tenant = configuration["Dashboard:TenantId"];
    var user = configuration["Dashboard:UserId"];
    if (!Guid.TryParse(tenant, out _) || !Guid.TryParse(user, out _)) return Results.Problem("Dashboard development identity is not configured.", statusCode: StatusCodes.Status503ServiceUnavailable);
    var claims = new[] { new Claim(ClaimTypes.NameIdentifier, user!), new Claim(ClaimTypes.Name, configuration["Dashboard:UserName"] ?? "operator"), new Claim("tenant_id", tenant!), new Claim(ClaimTypes.Role, configuration["Dashboard:Role"] ?? "SecurityAnalyst") };
    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)));
    return Results.Redirect("/");
});
app.MapGet("/auth/logout", async (HttpContext context) => { await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme); return Results.Redirect("/auth/login"); });
app.MapGet("/auth/denied", () => Results.Problem("You do not have access to this dashboard.", statusCode: StatusCodes.Status403Forbidden));

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
