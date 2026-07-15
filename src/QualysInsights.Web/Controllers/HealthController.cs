using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using QualysInsights.Application.Options;
using QualysInsights.Infrastructure.Persistence;

namespace QualysInsights.Web.Controllers;

[AllowAnonymous]
public sealed class HealthController(
    IOptions<QualysOptions> qualysOptions,
    IOptions<StorageOptions> storageOptions,
    QualysInsightsDbContext dbContext) : ApiControllerBase
{
    [HttpGet("/api/health")]
    public IActionResult LegacyHealth()
    {
        return Ok(new
        {
            status = "online",
            timestamp = DateTimeOffset.UtcNow.ToString("O"),
            qualysUrl = qualysOptions.Value.BaseUrl,
            version = "2.0.0",
            hasCredentials = !string.IsNullOrWhiteSpace(qualysOptions.Value.Username) && !string.IsNullOrWhiteSpace(qualysOptions.Value.Password)
        });
    }

    [HttpGet("/health")]
    public IActionResult Health()
    {
        return Ok(new { status = "healthy", timestamp = DateTimeOffset.UtcNow.ToString("O") });
    }

    [HttpGet("/health/ready")]
    public async Task<IActionResult> Ready(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(storageOptions.Value.DataDirectory);
        var probePath = Path.Combine(storageOptions.Value.DataDirectory, $".ready-{Guid.NewGuid():N}.tmp");
        await System.IO.File.WriteAllTextAsync(probePath, "ok", cancellationToken);
        System.IO.File.Delete(probePath);

        var canConnect = await dbContext.Database.CanConnectAsync(cancellationToken);
        return canConnect
            ? Ok(new { status = "ready", storage = "writable", database = "available", timestamp = DateTimeOffset.UtcNow.ToString("O") })
            : StatusCode(StatusCodes.Status503ServiceUnavailable, new { status = "not-ready", database = "unavailable" });
    }
}

