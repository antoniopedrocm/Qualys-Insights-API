using QualysInsights.Application.DTOs;

namespace QualysInsights.Application.Interfaces;

public interface IQualysClient
{
    Task<IReadOnlyList<HostDto>> GetHostListAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<VulnerabilityDto>> GetVulnerabilitiesAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<ScanDto>> GetScanListAsync(CancellationToken cancellationToken);
    Task<DetectionDto?> GetDetectionByIdAsync(string detectionId, CancellationToken cancellationToken);
    Task<IReadOnlyList<DetectionDto>> GetHostDetectionsWithDetailsAsync(CancellationToken cancellationToken);
}

