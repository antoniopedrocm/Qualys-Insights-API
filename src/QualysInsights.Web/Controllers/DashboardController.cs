using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using QualysInsights.Application.Interfaces;
using QualysInsights.Application.Models;

namespace QualysInsights.Web.Controllers;

[Authorize(Policy = "QualysInsightsAccess")]
[Route("api/dashboard")]
public sealed class DashboardController(IQualysDataService service, ILogger<DashboardController> logger) : ApiControllerBase
{
    [HttpGet("summary")]
    [EnableRateLimiting("heavy")]
    public async Task<IActionResult> Summary(CancellationToken cancellationToken)
    {
        try
        {
            var result = await service.GetDashboardSummaryAsync(cancellationToken);
            var payload = new { cached = result.Cached, stale = result.Stale, data = result.Data };
            if (result.Error is QualysQueueException queue)
            {
                return QueueResponse(queue, payload);
            }

            return Ok(new { success = true, payload.cached, payload.stale, payload.data });
        }
        catch (QualysQueueException ex)
        {
            return QueueResponse(ex);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Erro em /api/dashboard/summary.");
            return StatusCode(StatusCodes.Status500InternalServerError, ErrorBody("Erro ao gerar resumo", ex.Message));
        }
    }

    [HttpGet("trends")]
    [EnableRateLimiting("heavy")]
    public async Task<IActionResult> Trends(CancellationToken cancellationToken)
    {
        try
        {
            var result = await service.GetDashboardTrendsAsync(cancellationToken);
            var payload = new { cached = result.Cached, stale = result.Stale, data = result.Data };
            if (result.Error is QualysQueueException queue)
            {
                return QueueResponse(queue, payload);
            }

            return Ok(new { success = true, payload.cached, payload.stale, payload.data });
        }
        catch (QualysQueueException ex)
        {
            return QueueResponse(ex);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Erro em /api/dashboard/trends.");
            return StatusCode(StatusCodes.Status500InternalServerError, ErrorBody("Erro ao gerar tendencias", ex.Message));
        }
    }
}

