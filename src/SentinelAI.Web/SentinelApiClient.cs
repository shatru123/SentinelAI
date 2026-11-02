using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
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

public sealed class ApiAuthenticationException : Exception
{
    public ApiAuthenticationException() : base("An authenticated API token is unavailable for this circuit.") { }
}

public sealed class SentinelApiClient(IHttpClientFactory httpClientFactory, ILogger<SentinelApiClient> logger)
{
    public async Task<PagedResponse<T>> GetPageAsync<T>(string endpoint, int page, int pageSize, CancellationToken cancellationToken = default)
    {
        var normalizedPage = Math.Max(1, page);
        var normalizedPageSize = Math.Clamp(pageSize, 1, 100);
        var requestPath = $"{endpoint}?page={normalizedPage}&pageSize={normalizedPageSize}";
        try
        {
            using var response = await httpClientFactory.CreateClient("SentinelApi").GetAsync(requestPath, cancellationToken);
            if (!response.IsSuccessStatusCode) throw CreateHttpFailure(response.StatusCode, endpoint);

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

    private SentinelApiException CreateHttpFailure(HttpStatusCode statusCode, string endpoint)
    {
        var (kind, message) = statusCode switch
        {
            HttpStatusCode.Unauthorized => (SentinelApiFailureKind.AuthenticationRequired, "Your session has expired or authentication is required. Sign in again."),
            HttpStatusCode.Forbidden => (SentinelApiFailureKind.Forbidden, "You do not have permission to view this data."),
            HttpStatusCode.NotFound => (SentinelApiFailureKind.NotFound, "The requested API endpoint was not found."),
            >= HttpStatusCode.InternalServerError => (SentinelApiFailureKind.ServerError, "The API encountered an error. Try again later."),
            _ => (SentinelApiFailureKind.Unexpected, "The API returned an unexpected error. Try again.")
        };
        logger.LogWarning("The API returned HTTP {StatusCode} for {Endpoint}.", (int)statusCode, endpoint);
        return new SentinelApiException(kind, message);
    }
}
