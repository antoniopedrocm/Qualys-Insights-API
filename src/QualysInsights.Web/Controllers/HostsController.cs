using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using QualysInsights.Application.Interfaces;

namespace QualysInsights.Web.Controllers;

[Authorize(Policy = "QualysInsightsAccess")]
[Route("api/hosts")]
public sealed class HostsController(IQualysDataService service, ILogger<HostsController> logger) : ApiControllerBase
{
    [HttpGet]
    [EnableRateLimiting("heavy")]
    public async Task<IActionResult> Get(CancellationToken cancellationToken)
    {
        try
        {
            var result = await service.GetHostsAsync(cancellationToken);
            return Ok(new { success = true, total = result.Data.Count, cached = result.Cached, stale = result.Stale, data = result.Data });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Erro em /api/hosts.");
            return StatusCode(StatusCodes.Status500InternalServerError, ErrorBody("Erro ao buscar hosts", ex.Message));
        }
    }
}

