namespace SentinelAI.Web;

public static class SentinelApiAuthentication
{
    public const string AccessTokenClaim = "sentinelai_access_token";
}

public sealed class ApiAuthenticationException : Exception
{
    public ApiAuthenticationException() : base("An authenticated API token is unavailable for this request.") { }
}
