using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using QualysInsights.Application.Interfaces;

namespace QualysInsights.Web.Controllers;

[Authorize(Policy = "QualysInsightsAccess")]
[Route("api/scans")]
public sealed class ScansController(IQualysDataService service, ILogger<ScansController> logger) : ApiControllerBase
{
    [HttpGet]
    [EnableRateLimiting("heavy")]
    public async Task<IActionResult> Get(CancellationToken cancellationToken)
    {
        try
        {
            var scans = await service.GetScansAsync(cancellationToken);
            return Ok(new { success = true, total = scans.Count, data = scans });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Erro em /api/scans.");
            return StatusCode(StatusCodes.Status500InternalServerError, ErrorBody("Erro ao buscar scans", ex.Message));
        }
    }
}

