using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using SentinelAI.Web;

namespace SentinelAI.UnitTests;

public sealed class WebProductionConfigurationValidatorTests
{
    [Fact]
    public void Production_requires_oidc_https_api_and_trusted_proxy_configuration()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Authentication:Authority"] = "http://identity.example.com/",
            ["Authentication:ClientId"] = "sentinelai-web",
            ["Authentication:ClientSecret"] = "managed-secret",
            ["Api:BaseUrl"] = "http://api.internal",
            ["Security:RequireHttps"] = "false",
            ["AllowedHosts"] = "*",
            ["Api:UseDevelopmentHeaders"] = "true"
        }).Build();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            WebProductionConfigurationValidator.Validate(configuration, new TestEnvironment()));

        Assert.Contains("Authentication:Authority", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Api:BaseUrl", exception.Message, StringComparison.Ordinal);
        Assert.Contains("ReverseProxy:KnownProxies", exception.Message, StringComparison.Ordinal);
        Assert.Contains("AllowedHosts", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Development identity headers", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Production_accepts_oidc_and_tls_api_configuration()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Authentication:Authority"] = "https://identity.example.com/",
            ["Authentication:ClientId"] = "sentinelai-web",
            ["Authentication:ClientSecret"] = "managed-secret",
            ["Api:BaseUrl"] = "https://api.sentinelai.example.com",
            ["Security:RequireHttps"] = "true",
            ["ReverseProxy:KnownProxies:0"] = "10.0.0.10",
            ["AllowedHosts"] = "sentinelai.example.com"
        }).Build();

        var exception = Record.Exception(() =>
            WebProductionConfigurationValidator.Validate(configuration, new TestEnvironment()));

        Assert.Null(exception);
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Production";
        public string ApplicationName { get; set; } = "SentinelAI.UnitTests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
