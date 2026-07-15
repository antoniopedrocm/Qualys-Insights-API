using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using QualysInsights.Application.Interfaces;

namespace QualysInsights.Web.Controllers;

[Authorize(Policy = "QualysInsightsAccess")]
[Route("api/detections")]
public sealed class DetectionsController(IQualysDataService service, IExportService exportService, ILogger<DetectionsController> logger) : ApiControllerBase
{
    [HttpGet("enriched")]
    [EnableRateLimiting("heavy")]
    public async Task<IActionResult> Enriched([FromQuery] string? format, CancellationToken cancellationToken)
    {
        try
        {
            var detections = await service.GetEnrichedDetectionsAsync(cancellationToken);
            if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
            {
                return File(exportService.BuildDetectionsCsv(detections), "text/csv; charset=utf-8", "detections.csv");
            }

            if (string.Equals(format, "xlsx", StringComparison.OrdinalIgnoreCase))
            {
                return File(exportService.BuildDetectionsWorkbook(detections), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "detections.xlsx");
            }

            return Ok(new { success = true, total = detections.Count, data = detections });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Erro em /api/detections/enriched.");
            return StatusCode(StatusCodes.Status500InternalServerError, ErrorBody("Erro ao buscar detecções com detalhes", ex.Message));
        }
    }
}

