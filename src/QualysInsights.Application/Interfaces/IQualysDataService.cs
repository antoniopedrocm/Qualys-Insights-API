using QualysInsights.Application.DTOs;
using QualysInsights.Application.Models;

namespace QualysInsights.Application.Interfaces;

public interface IQualysDataService
{
    Task<CacheResult<IReadOnlyList<HostDto>>> GetHostsAsync(CancellationToken cancellationToken);
    Task<CacheResult<IReadOnlyList<VulnerabilityDto>>> GetVulnerabilitiesAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<ScanDto>> GetScansAsync(CancellationToken cancellationToken);
    Task<CacheResult<DashboardSummaryDto>> GetDashboardSummaryAsync(CancellationToken cancellationToken);
    Task<CacheResult<DashboardTrendsDto>> GetDashboardTrendsAsync(CancellationToken cancellationToken);
    Task<EffectivenessResponse> AnalyzeEffectivenessAsync(IReadOnlyList<string> detectionIds, CancellationToken cancellationToken);
    Task<EffectivenessCacheDto> GetEffectivenessCacheAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<DetectionDto>> GetEnrichedDetectionsAsync(CancellationToken cancellationToken);
    Task<(LegacyEffectivenessSummaryDto Summary, IReadOnlyList<DetectionDto> Detections, IReadOnlyList<string> AttemptedIds)> CalculateLegacyEffectivenessAsync(CancellationToken cancellationToken);
}

