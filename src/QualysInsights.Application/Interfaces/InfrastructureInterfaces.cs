using QualysInsights.Application.DTOs;
using QualysInsights.Application.Models;

namespace QualysInsights.Application.Interfaces;

public interface ICachedDataProvider
{
    Task<CacheResult<T>> GetAsync<T>(string key, Func<CancellationToken, Task<T>> factory, CancellationToken cancellationToken);
}

public interface IEffectivenessCacheStore
{
    Task<EffectivenessCacheDto> LoadAsync(CancellationToken cancellationToken);
    Task<EffectivenessCacheDto> UpsertManyAsync(IReadOnlyList<EffectivenessItemDto> items, EffectivenessCacheMetaDto meta, CancellationToken cancellationToken);
}

public interface IExportService
{
    byte[] BuildVulnerabilitiesWorkbook(IReadOnlyList<VulnerabilityDto> vulnerabilities);
    byte[] BuildVulnerabilitiesCsv(IReadOnlyList<VulnerabilityDto> vulnerabilities);
    byte[] BuildDetectionsWorkbook(IReadOnlyList<DetectionDto> detections);
    byte[] BuildDetectionsCsv(IReadOnlyList<DetectionDto> detections);
}

public interface IDetectionIdFileReader
{
    Task<IReadOnlyList<string>> ReadDetectionIdsAsync(CancellationToken cancellationToken);
}

public interface ILegacyEffectivenessCacheMigrator
{
    Task MigrateIfEnabledAsync(CancellationToken cancellationToken);
}

