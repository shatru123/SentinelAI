using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts;

namespace SentinelAI.Web;

public enum SentinelApiFailureKind
{
    Unavailable,
    AuthenticationRequired,
    Forbidden,
    NotFound,
    ServerError,
    InvalidResponse,
    Timeout,
    Unexpected
}

public sealed class SentinelApiException(SentinelApiFailureKind kind, string userMessage, Exception? innerException = null)
    : Exception(userMessage, innerException)
{
    public SentinelApiFailureKind Kind { get; } = kind;
    public string UserMessage { get; } = userMessage;
}

public sealed class SentinelApiClient(
    IHttpClientFactory httpClientFactory,
    IHttpContextAccessor httpContextAccessor,
    AuthenticationStateProvider authenticationStateProvider,
    IHostEnvironment environment,
    IConfiguration configuration,
    ILogger<SentinelApiClient> logger)
{
    public Task<PagedResponse<T>> GetPageAsync<T>(string endpoint, int page, int pageSize, CancellationToken cancellationToken = default)
        => GetPageAsync<T>(endpoint, page, pageSize, null, cancellationToken);

    public async Task<PagedResponse<T>> GetPageAsync<T>(string endpoint, int page, int pageSize, IDictionary<string, string?>? parameters, CancellationToken cancellationToken = default)
    {
        var normalizedPage = Math.Max(1, page);
        var normalizedPageSize = Math.Clamp(pageSize, 1, 100);
        var query = new System.Text.StringBuilder($"{endpoint}?page={normalizedPage}&pageSize={normalizedPageSize}");
        if (parameters is not null)
        {
            foreach (var (key, value) in parameters)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    query.Append('&').Append(Uri.EscapeDataString(key)).Append('=').Append(Uri.EscapeDataString(value));
            }
        }
        var requestPath = query.ToString();
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, requestPath);
            using var response = await SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode) throw await CreateHttpFailureAsync(response, endpoint, cancellationToken);

            PagedResponse<T>? result;
            try
            {
                result = await response.Content.ReadFromJsonAsync<PagedResponse<T>>(cancellationToken);
            }
            catch (JsonException exception)
            {
                logger.LogWarning(exception, "The API returned invalid JSON for {Endpoint}.", endpoint);
                throw new SentinelApiException(SentinelApiFailureKind.InvalidResponse, "The API returned an invalid response. Try again.", exception);
            }
            catch (NotSupportedException exception)
            {
                logger.LogWarning(exception, "The API returned an unsupported response for {Endpoint}.", endpoint);
                throw new SentinelApiException(SentinelApiFailureKind.InvalidResponse, "The API returned an invalid response. Try again.", exception);
            }

            if (result is null)
            {
                logger.LogWarning("The API returned an empty response for {Endpoint}.", endpoint);
                throw new SentinelApiException(SentinelApiFailureKind.InvalidResponse, "The API returned an invalid response. Try again.");
            }

            return result with { Items = result.Items ?? Array.Empty<T>() };
        }
        catch (SentinelApiException) { throw; }
        catch (ApiAuthenticationException exception)
        {
            logger.LogWarning("Authenticated API access was unavailable for {Endpoint}.", endpoint);
            throw new SentinelApiException(SentinelApiFailureKind.AuthenticationRequired, "Your session has expired or authentication is required. Sign in again.", exception);
        }
        catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("The API request timed out for {Endpoint}.", endpoint);
            throw new SentinelApiException(SentinelApiFailureKind.Timeout, "The API request timed out. Try again.", exception);
        }
        catch (HttpRequestException exception)
        {
            logger.LogWarning(exception, "The API could not be reached for {Endpoint}.", endpoint);
            throw new SentinelApiException(SentinelApiFailureKind.Unavailable, "The API is unavailable. Start the API and try again.", exception);
        }
    }

    public async Task<T> GetJsonAsync<T>(string endpoint, CancellationToken cancellationToken = default)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            using var response = await SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode) throw await CreateHttpFailureAsync(response, endpoint, cancellationToken);
            return await response.Content.ReadFromJsonAsync<T>(cancellationToken)
                ?? throw new SentinelApiException(SentinelApiFailureKind.InvalidResponse, "The API returned an invalid response. Try again.");
        }
        catch (SentinelApiException) { throw; }
        catch (ApiAuthenticationException exception) { throw new SentinelApiException(SentinelApiFailureKind.AuthenticationRequired, "Your session has expired or authentication is required. Sign in again.", exception); }
        catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested) { throw new SentinelApiException(SentinelApiFailureKind.Timeout, "The API request timed out. Try again.", exception); }
        catch (HttpRequestException exception) { logger.LogWarning(exception, "The API could not be reached for {Endpoint}.", endpoint); throw new SentinelApiException(SentinelApiFailureKind.Unavailable, "The API is unavailable. Start the API and try again.", exception); }
        catch (JsonException exception) { logger.LogWarning(exception, "The API returned invalid JSON for {Endpoint}.", endpoint); throw new SentinelApiException(SentinelApiFailureKind.InvalidResponse, "The API returned an invalid response. Try again.", exception); }
    }

    public async Task<byte[]> GetBytesAsync(string endpoint, CancellationToken cancellationToken = default)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            using var response = await SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode) throw await CreateHttpFailureAsync(response, endpoint, cancellationToken);
            return await response.Content.ReadAsByteArrayAsync(cancellationToken);
        }
        catch (SentinelApiException) { throw; }
        catch (ApiAuthenticationException exception) { throw new SentinelApiException(SentinelApiFailureKind.AuthenticationRequired, "Your session has expired or authentication is required. Sign in again.", exception); }
        catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested) { throw new SentinelApiException(SentinelApiFailureKind.Timeout, "The API request timed out. Try again.", exception); }
        catch (HttpRequestException exception) { throw new SentinelApiException(SentinelApiFailureKind.Unavailable, "The API is unavailable. Start the API and try again.", exception); }
    }

    public async Task PostAsync(string endpoint, CancellationToken cancellationToken = default)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
            using var response = await SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode) throw await CreateHttpFailureAsync(response, endpoint, cancellationToken);
        }
        catch (SentinelApiException) { throw; }
        catch (ApiAuthenticationException exception) { throw new SentinelApiException(SentinelApiFailureKind.AuthenticationRequired, "Your session has expired or authentication is required. Sign in again.", exception); }
        catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested) { throw new SentinelApiException(SentinelApiFailureKind.Timeout, "The API request timed out. Try again.", exception); }
        catch (HttpRequestException exception) { throw new SentinelApiException(SentinelApiFailureKind.Unavailable, "The API is unavailable. Start the API and try again.", exception); }
    }

    public async Task<TResponse> PostJsonAsync<TRequest, TResponse>(string endpoint, TRequest payload, CancellationToken cancellationToken = default)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
            {
                Content = JsonContent.Create(payload)
            };
            using var response = await SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode) throw await CreateHttpFailureAsync(response, endpoint, cancellationToken);

            try
            {
                var result = await response.Content.ReadFromJsonAsync<TResponse>(cancellationToken);
                return result ?? throw new SentinelApiException(SentinelApiFailureKind.InvalidResponse, "The API returned an invalid response. Try again.");
            }
            catch (JsonException exception)
            {
                logger.LogWarning(exception, "The API returned invalid JSON for {Endpoint}.", endpoint);
                throw new SentinelApiException(SentinelApiFailureKind.InvalidResponse, "The API returned an invalid response. Try again.", exception);
            }
            catch (NotSupportedException exception)
            {
                logger.LogWarning(exception, "The API returned an unsupported response for {Endpoint}.", endpoint);
                throw new SentinelApiException(SentinelApiFailureKind.InvalidResponse, "The API returned an invalid response. Try again.", exception);
            }
        }
        catch (SentinelApiException) { throw; }
        catch (ApiAuthenticationException exception)
        {
            logger.LogWarning("Authenticated API access was unavailable for {Endpoint}.", endpoint);
            throw new SentinelApiException(SentinelApiFailureKind.AuthenticationRequired, "Your session has expired or authentication is required. Sign in again.", exception);
        }
        catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("The API request timed out for {Endpoint}.", endpoint);
            throw new SentinelApiException(SentinelApiFailureKind.Timeout, "The API request timed out. Try again.", exception);
        }
        catch (HttpRequestException exception)
        {
            logger.LogWarning(exception, "The API could not be reached for {Endpoint}.", endpoint);
            throw new SentinelApiException(SentinelApiFailureKind.Unavailable, "The API is unavailable. Start the API and try again.", exception);
        }
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var context = httpContextAccessor.HttpContext;
        ClaimsPrincipal principal;
        if (context is not null)
        {
            principal = context.User;
        }
        else
        {
            try
            {
                principal = (await authenticationStateProvider.GetAuthenticationStateAsync()).User;
            }
            catch (InvalidOperationException exception)
            {
                logger.LogWarning(exception, "Interactive authentication state is unavailable for an API request.");
                throw new ApiAuthenticationException();
            }
        }

        if (principal.Identity?.IsAuthenticated != true) throw new ApiAuthenticationException();

        var accessToken = context is null
            ? principal.FindFirstValue(SentinelApiAuthentication.AccessTokenClaim)
            : await context.GetTokenAsync("access_token") ?? principal.FindFirstValue(SentinelApiAuthentication.AccessTokenClaim);

        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        }
        else if (environment.IsDevelopment() && IsDevelopmentHeadersEnabled())
        {
            AddClaimHeader(request, "X-Tenant-Id", principal.FindFirstValue("tenant_id"));
            AddClaimHeader(request, "X-User-Id", principal.FindFirstValue(ClaimTypes.NameIdentifier));
            AddClaimHeader(request, "X-Role", principal.FindFirstValue(ClaimTypes.Role));
            AddClaimHeader(request, "X-User-Name", principal.Identity.Name);
        }
        else
        {
            logger.LogWarning("Authenticated API request was blocked because no bearer token is available.");
            throw new ApiAuthenticationException();
        }

        return await httpClientFactory.CreateClient("SentinelApi").SendAsync(request, cancellationToken);
    }

    private bool IsDevelopmentHeadersEnabled() =>
        configuration.GetValue<bool>("Api:UseDevelopmentHeaders") ||
        configuration.GetValue<bool>("Authentication:UseDevelopmentHeaders");

    private static void AddClaimHeader(HttpRequestMessage request, string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) request.Headers.TryAddWithoutValidation(name, value);
    }

    private async Task<SentinelApiException> CreateHttpFailureAsync(
        HttpResponseMessage response,
        string endpoint,
        CancellationToken cancellationToken)
    {
        var statusCode = response.StatusCode;
        var (kind, message) = statusCode switch
        {
            HttpStatusCode.Unauthorized => (SentinelApiFailureKind.AuthenticationRequired, "Your session has expired or authentication is required. Sign in again."),
            HttpStatusCode.Forbidden => (SentinelApiFailureKind.Forbidden, "You do not have permission to perform this action."),
            HttpStatusCode.NotFound => (SentinelApiFailureKind.NotFound, "The requested API endpoint or resource was not found."),
            >= HttpStatusCode.InternalServerError => (SentinelApiFailureKind.ServerError, "The API encountered an error. Try again later."),
            _ => (SentinelApiFailureKind.Unexpected, "The API rejected the request.")
        };

        var detail = await TryReadProblemDetailAsync(response.Content, cancellationToken);
        if (environment.IsDevelopment() && !string.IsNullOrWhiteSpace(detail) &&
            statusCode is not HttpStatusCode.Unauthorized and not HttpStatusCode.Forbidden)
        {
            message = $"{message} Details: {detail}";
        }

        logger.LogWarning("The API returned HTTP {StatusCode} for {Endpoint}.", (int)statusCode, endpoint);
        return new SentinelApiException(kind, message);
    }

    private static async Task<string?> TryReadProblemDetailAsync(HttpContent content, CancellationToken cancellationToken)
    {
        const int maxBytes = 16 * 1024;
        try
        {
            await using var source = await content.ReadAsStreamAsync(cancellationToken);
            using var buffer = new MemoryStream();
            var chunk = new byte[4096];
            while (buffer.Length < maxBytes)
            {
                var remaining = (int)Math.Min(chunk.Length, maxBytes - buffer.Length);
                var read = await source.ReadAsync(chunk.AsMemory(0, remaining), cancellationToken);
                if (read == 0) break;
                await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
            }

            if (buffer.Length == 0) return null;
            using var document = JsonDocument.Parse(buffer.ToArray());
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;

            var detail = root.TryGetProperty("detail", out var detailElement) && detailElement.ValueKind == JsonValueKind.String
                ? detailElement.GetString()
                : null;
            var title = root.TryGetProperty("title", out var titleElement) && titleElement.ValueKind == JsonValueKind.String
                ? titleElement.GetString()
                : null;
            var result = !string.IsNullOrWhiteSpace(detail) ? detail : title;
            if (string.IsNullOrWhiteSpace(result)) return null;
            return result.Length <= 1_000 ? result : result[..1_000];
        }
        catch (Exception exception) when (exception is JsonException or IOException or NotSupportedException)
        {
            return null;
        }
    }
}
