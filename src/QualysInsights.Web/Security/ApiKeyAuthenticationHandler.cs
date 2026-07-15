using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using QualysInsights.Application.Options;

namespace QualysInsights.Web.Security;

public sealed class ApiKeyAuthenticationSchemeOptions : AuthenticationSchemeOptions;

public sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<ApiKeyAuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IOptions<AppAuthenticationOptions> appOptions)
    : AuthenticationHandler<ApiKeyAuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "QualysInsightsApiKey";
    private const string HeaderName = "X-QualysInsights-ApiKey";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(HeaderName, out var apiKeyValues))
        {
            return Task.FromResult(AuthenticateResult.Fail("API key header is missing."));
        }

        var configuredHash = appOptions.Value.ApiKeySha256.Trim();
        var providedHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(apiKeyValues.ToString()))).ToLowerInvariant();
        if (!FixedTimeEquals(configuredHash, providedHash))
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid API key."));
        }

        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, "api-key-client")],
            SchemeName);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }

    private static bool FixedTimeEquals(string expected, string actual)
    {
        var expectedBytes = Encoding.UTF8.GetBytes(expected.ToLowerInvariant());
        var actualBytes = Encoding.UTF8.GetBytes(actual.ToLowerInvariant());
        return expectedBytes.Length == actualBytes.Length && CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
    }
}

