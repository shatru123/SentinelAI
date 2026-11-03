using System.Net;
using SentinelAI.Agent.Vulnerability;

namespace SentinelAI.UnitTests;

public sealed class NvdFeedPaginationTests
{
    [Fact]
    public void ParsePage_preserves_pagination_metadata_and_empty_result_pages()
    {
        const string json = """
        {"totalResults":0,"startIndex":0,"resultsPerPage":2000,"vulnerabilities":[]}
        """;

        var page = NvdCveFeedParser.ParsePage(json);

        Assert.Equal(0, page.TotalResults);
        Assert.Equal(0, page.StartIndex);
        Assert.Equal(2000, page.ResultsPerPage);
        Assert.Empty(page.Vulnerabilities);
    }

    [Fact]
    public void ParsePage_rejects_missing_or_invalid_pagination_metadata()
    {
        const string json = """
        {"totalResults":3,"startIndex":4,"resultsPerPage":2,"vulnerabilities":[]}
        """;

        Assert.Throws<System.Text.Json.JsonException>(() => NvdCveFeedParser.ParsePage(json));
    }

    [Fact]
    public async Task Modified_date_client_builds_bounded_paged_request()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""{"totalResults":0,"startIndex":0,"resultsPerPage":100,"vulnerabilities":[]}""")
        });
        using var client = new HttpClient(handler);
        NvdCveFeedClient.Configure(client);
        var feed = new NvdCveFeedClient(client);
        var start = new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);
        var end = new DateTimeOffset(2026, 10, 8, 0, 0, 0, TimeSpan.Zero);

        var page = await feed.GetModifiedPageAsync(start, end, 0, 100);

        Assert.Equal(0, page.TotalResults);
        Assert.NotNull(handler.RequestUri);
        Assert.Contains("lastModStartDate=", handler.RequestUri!.Query);
        Assert.Contains("lastModEndDate=", handler.RequestUri.Query);
        Assert.Contains("resultsPerPage=100", handler.RequestUri.Query);
        Assert.Contains("startIndex=0", handler.RequestUri.Query);
    }

    [Fact]
    public async Task Modified_date_client_rejects_windows_larger_than_120_days_before_network_call()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        using var client = new HttpClient(handler);
        NvdCveFeedClient.Configure(client);
        var feed = new NvdCveFeedClient(client);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => feed.GetModifiedPageAsync(
            DateTimeOffset.UtcNow.AddDays(-121), DateTimeOffset.UtcNow, 0, 100));
        Assert.Null(handler.RequestUri);
    }

    [Fact]
    public async Task Modified_date_client_rejects_excessive_page_sizes_before_network_call()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        using var client = new HttpClient(handler);
        NvdCveFeedClient.Configure(client);
        var feed = new NvdCveFeedClient(client);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => feed.GetModifiedPageAsync(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow, 0, 2001));
        Assert.Null(handler.RequestUri);
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory) : HttpMessageHandler
    {
        public Uri? RequestUri { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestUri = request.RequestUri;
            return Task.FromResult(responseFactory(request));
        }
    }
}
