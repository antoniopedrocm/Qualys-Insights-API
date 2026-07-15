using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using QualysInsights.Application.Interfaces;
using QualysInsights.Application.Models;
using QualysInsights.Application.Services;

namespace QualysInsights.Web.Controllers;

[Authorize(Policy = "QualysInsightsAccess")]
[Route("api/vulnerabilities")]
public sealed class VulnerabilitiesController(IQualysDataService service, ILogger<VulnerabilitiesController> logger) : ApiControllerBase
{
    [HttpGet]
    [EnableRateLimiting("heavy")]
    public async Task<IActionResult> Get(CancellationToken cancellationToken)
    {
        try
        {
            var result = await service.GetVulnerabilitiesAsync(cancellationToken);
            var totalFixed = result.Data.Count(vuln => BusinessClassifiers.IsDetectionFixed(vuln) || vuln.IsFixed);
            logger.LogInformation("Vulnerability count. TotalFixed={TotalFixed} TotalOpen={TotalOpen}", totalFixed, result.Data.Count - totalFixed);

            var payload = new { total = result.Data.Count, cached = result.Cached, stale = result.Stale, data = result.Data };
            if (result.Error is QualysQueueException queue)
            {
                return QueueResponse(queue, payload);
            }

            return Ok(new { success = true, payload.total, payload.cached, payload.stale, payload.data });
        }
        catch (QualysQueueException ex)
        {
            return QueueResponse(ex);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Erro em /api/vulnerabilities.");
            return StatusCode(StatusCodes.Status502BadGateway, ErrorBody("Erro ao buscar vulnerabilidades", ex.Message));
        }
    }
}

