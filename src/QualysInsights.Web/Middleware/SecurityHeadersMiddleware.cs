using Microsoft.Extensions.Options;
using QualysInsights.Application.Options;

namespace QualysInsights.Web.Middleware;

public sealed class SecurityHeadersMiddleware(RequestDelegate next, IOptions<SecurityHeadersOptions> options)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;
        headers.TryAdd("Content-Security-Policy", options.Value.ContentSecurityPolicy);
        headers.TryAdd("X-Frame-Options", "DENY");
        headers.TryAdd("X-Content-Type-Options", "nosniff");
        headers.TryAdd("Referrer-Policy", "strict-origin-when-cross-origin");
        headers.TryAdd("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

        await next(context);
    }
}

