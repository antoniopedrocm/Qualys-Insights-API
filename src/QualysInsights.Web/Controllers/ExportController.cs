using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using QualysInsights.Application.Interfaces;

namespace QualysInsights.Web.Controllers;

[Authorize(Policy = "QualysInsightsAccess")]
[Route("api/export/vulnerabilities")]
public sealed class ExportController(IQualysDataService service, IExportService exportService, ILogger<ExportController> logger) : ApiControllerBase
{
    [HttpGet("excel")]
    [EnableRateLimiting("heavy")]
    public async Task<IActionResult> Excel(CancellationToken cancellationToken)
    {
        try
        {
            var vulnerabilities = (await service.GetVulnerabilitiesAsync(cancellationToken)).Data;
            if (vulnerabilities.Count == 0)
            {
                return NotFound(new { success = false, error = "Nenhuma vulnerabilidade encontrada" });
            }

            var timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH-mm-ss-fffffffZ");
            return File(
                exportService.BuildVulnerabilitiesWorkbook(vulnerabilities),
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                SanitizeFileName($"qualys_vulnerabilities_{timestamp}.xlsx"));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Erro em /api/export/vulnerabilities/excel.");
            return StatusCode(StatusCodes.Status500InternalServerError, ErrorBody("Erro ao exportar Excel", ex.Message));
        }
    }

    [HttpGet("csv")]
    [EnableRateLimiting("heavy")]
    public async Task<IActionResult> Csv(CancellationToken cancellationToken)
    {
        try
        {
            var vulnerabilities = (await service.GetVulnerabilitiesAsync(cancellationToken)).Data;
            if (vulnerabilities.Count == 0)
            {
                return NotFound(new { success = false, error = "Nenhuma vulnerabilidade encontrada" });
            }

            var timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH-mm-ss-fffffffZ");
            return File(exportService.BuildVulnerabilitiesCsv(vulnerabilities), "text/csv; charset=utf-8", SanitizeFileName($"qualys_vulnerabilities_{timestamp}.csv"));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Erro em /api/export/vulnerabilities/csv.");
            return StatusCode(StatusCodes.Status500InternalServerError, ErrorBody("Erro ao exportar CSV", ex.Message));
        }
    }

    private static string SanitizeFileName(string fileName)
    {
        foreach (var invalidChar in Path.GetInvalidFileNameChars())
        {
            fileName = fileName.Replace(invalidChar.ToString(), "-", StringComparison.Ordinal);
        }

        return fileName;
    }
}
