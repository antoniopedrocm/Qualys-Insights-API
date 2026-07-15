using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using QualysInsights.Application.DTOs;
using QualysInsights.Application.Interfaces;
using QualysInsights.Application.Models;
using QualysInsights.Application.Services;

namespace QualysInsights.Web.Controllers;

[Authorize(Policy = "QualysInsightsAccess")]
public sealed class EffectivenessController(IQualysDataService service, ILogger<EffectivenessController> logger) : ApiControllerBase
{
    [HttpPost("/api/effectiveness")]
    [EnableRateLimiting("heavy")]
    public async Task<IActionResult> Analyze([FromBody] EffectivenessRequest request, CancellationToken cancellationToken)
    {
        var ids = request.DetectionIds is { Count: > 0 }
            ? request.DetectionIds
            : DetectionIdClassifier.Parse(request.Input);

        if (ids.Count == 0)
        {
            return BadRequest(new
            {
                success = false,
                error = "Nenhum Detection ID informado.",
                message = "Informe pelo menos um Detection ID para análise."
            });
        }

        try
        {
            return Ok(await service.AnalyzeEffectivenessAsync(ids, cancellationToken));
        }
        catch (QualysQueueException ex)
        {
            return QueueResponse(ex);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Erro em /api/effectiveness.");
            return StatusCode(StatusCodes.Status500InternalServerError, ErrorBody("Erro ao calcular efetividade", ex.Message));
        }
    }

    [HttpGet("/api/effectiveness/cache")]
    public async Task<IActionResult> Cache(CancellationToken cancellationToken)
    {
        try
        {
            var cache = await service.GetEffectivenessCacheAsync(cancellationToken);
            return Ok(new { success = true, meta = cache.Meta, items = cache.ItemsByDetectionId.Values });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Erro em /api/effectiveness/cache.");
            return StatusCode(StatusCodes.Status500InternalServerError, ErrorBody("Erro ao carregar cache de efetividade", ex.Message));
        }
    }

    [HttpPost("/efetividade/calcular")]
    [EnableRateLimiting("heavy")]
    public async Task<IActionResult> CalculateLegacy(CancellationToken cancellationToken)
    {
        try
        {
            var (summary, detections, attemptedIds) = await service.CalculateLegacyEffectivenessAsync(cancellationToken);
            if (detections.Count == 0)
            {
                return Ok(new
                {
                    success = false,
                    message = "Nenhuma detecção foi retornada pela API do Qualys para os IDs informados. Verifique se os IDs estão disponíveis na sua conta ou se há dados recentes na plataforma.",
                    attemptedDetectionIds = attemptedIds,
                    totalAttempted = attemptedIds.Count,
                    detections = Array.Empty<object>()
                });
            }

            return Ok(new
            {
                success = true,
                total_geral = summary.TotalGeral,
                windowLabels = summary.WindowLabels,
                DEV_QA = summary.Windows["DEV_QA"],
                PRD_Baixa = summary.Windows["PRD_Baixa"],
                PRD_Alta = summary.Windows["PRD_Alta"],
                detections
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Erro em /efetividade/calcular.");
            return BadRequest(new { success = false, error = ex.Message });
        }
    }
}

