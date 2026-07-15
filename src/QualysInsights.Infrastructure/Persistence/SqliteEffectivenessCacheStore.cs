using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QualysInsights.Application.DTOs;
using QualysInsights.Application.Interfaces;

namespace QualysInsights.Infrastructure.Persistence;

public sealed class SqliteEffectivenessCacheStore(QualysInsightsDbContext dbContext) : IEffectivenessCacheStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public async Task<EffectivenessCacheDto> LoadAsync(CancellationToken cancellationToken)
    {
        var meta = await dbContext.EffectivenessCacheMetadata.AsNoTracking().FirstOrDefaultAsync(cancellationToken);
        var items = await dbContext.EffectivenessItems.AsNoTracking().ToArrayAsync(cancellationToken);

        return new EffectivenessCacheDto
        {
            Meta = meta is null
                ? new EffectivenessCacheMetaDto()
                : new EffectivenessCacheMetaDto { GeneratedAt = meta.GeneratedAt, Source = meta.Source, Version = meta.Version },
            ItemsByDetectionId = items.ToDictionary(item => item.DetectionId, ToDto, StringComparer.OrdinalIgnoreCase)
        };
    }

    public async Task<EffectivenessCacheDto> UpsertManyAsync(IReadOnlyList<EffectivenessItemDto> items, EffectivenessCacheMetaDto meta, CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken);
        try
        {
            foreach (var item in items)
            {
                var detectionId = item.DetectionId.Trim();
                if (detectionId.Length == 0)
                {
                    continue;
                }

                var existing = await dbContext.EffectivenessItems.FindAsync([detectionId], cancellationToken);
                if (existing is null)
                {
                    dbContext.EffectivenessItems.Add(ToEntity(item));
                }
                else
                {
                    Merge(existing, item);
                }
            }

            var metadata = await dbContext.EffectivenessCacheMetadata.FindAsync([1], cancellationToken);
            if (metadata is null)
            {
                metadata = new EffectivenessCacheMetadataEntity { Id = 1 };
                dbContext.EffectivenessCacheMetadata.Add(metadata);
            }

            metadata.GeneratedAt = string.IsNullOrWhiteSpace(meta.GeneratedAt) ? DateTimeOffset.UtcNow.ToString("O") : meta.GeneratedAt;
            metadata.Source = string.IsNullOrWhiteSpace(meta.Source) ? "qualys-active-vulns-cache" : meta.Source;
            metadata.Version = meta.Version == 0 ? 1 : meta.Version;
            metadata.UpdatedAt = DateTimeOffset.UtcNow.ToString("O");

            await dbContext.SaveChangesAsync(cancellationToken);
            return await LoadAsync(cancellationToken);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private static EffectivenessItemEntity ToEntity(EffectivenessItemDto item)
    {
        return new EffectivenessItemEntity
        {
            DetectionId = item.DetectionId.Trim(),
            Status = item.Status,
            Dns = item.Dns,
            Ip = item.Ip,
            Title = item.Title,
            Severity = string.IsNullOrWhiteSpace(item.Severity) ? "Info" : item.Severity,
            Solution = item.Solution,
            HostTagsJson = JsonSerializer.Serialize(item.HostTags ?? Array.Empty<string>(), JsonOptions),
            LastSeen = item.LastSeen,
            UpdatedAt = DateTimeOffset.UtcNow.ToString("O")
        };
    }

    private static EffectivenessItemDto ToDto(EffectivenessItemEntity entity)
    {
        return new EffectivenessItemDto
        {
            DetectionId = entity.DetectionId,
            Status = entity.Status,
            Dns = entity.Dns,
            Ip = entity.Ip,
            Title = entity.Title,
            Severity = entity.Severity,
            Solution = entity.Solution,
            HostTags = DeserializeTags(entity.HostTagsJson),
            LastSeen = entity.LastSeen
        };
    }

    private static void Merge(EffectivenessItemEntity existing, EffectivenessItemDto next)
    {
        existing.Status = next.Status;
        existing.Dns = Coalesce(next.Dns, existing.Dns);
        existing.Ip = Coalesce(next.Ip, existing.Ip);
        existing.Title = Coalesce(next.Title, existing.Title);
        existing.Severity = Coalesce(next.Severity, existing.Severity, "Info");
        existing.Solution = Coalesce(next.Solution, existing.Solution);
        existing.HostTagsJson = JsonSerializer.Serialize(next.HostTags ?? DeserializeTags(existing.HostTagsJson), JsonOptions);
        existing.LastSeen = next.LastSeen;
        existing.UpdatedAt = DateTimeOffset.UtcNow.ToString("O");
    }

    private static string Coalesce(params string?[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? "";
    }

    private static IReadOnlyList<string> DeserializeTags(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<IReadOnlyList<string>>(json, JsonOptions) ?? Array.Empty<string>();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }
}

