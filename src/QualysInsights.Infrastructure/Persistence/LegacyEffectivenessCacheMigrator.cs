using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using QualysInsights.Application.DTOs;
using QualysInsights.Application.Interfaces;
using QualysInsights.Application.Options;

namespace QualysInsights.Infrastructure.Persistence;

public sealed class LegacyEffectivenessCacheMigrator(
    IOptions<StorageOptions> storageOptions,
    IEffectivenessCacheStore store,
    ILogger<LegacyEffectivenessCacheMigrator> logger) : ILegacyEffectivenessCacheMigrator
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task MigrateIfEnabledAsync(CancellationToken cancellationToken)
    {
        var options = storageOptions.Value;
        if (!options.MigrateLegacyJsonOnStartup)
        {
            logger.LogInformation("Legacy effectiveness cache migration disabled.");
            return;
        }

        var path = ResolvePath(options.LegacyEffectivenessCachePath);
        if (!File.Exists(path))
        {
            logger.LogInformation("Legacy effectiveness cache not found. Path={LegacyCachePath}", path);
            return;
        }

        try
        {
            await using var stream = File.OpenRead(path);
            var legacy = await JsonSerializer.DeserializeAsync<EffectivenessCacheDto>(stream, JsonOptions, cancellationToken);
            if (legacy?.ItemsByDetectionId is null || legacy.ItemsByDetectionId.Count == 0)
            {
                logger.LogInformation("Legacy effectiveness cache migration skipped because no items were found.");
                return;
            }

            var existing = await store.LoadAsync(cancellationToken);
            var missingItems = legacy.ItemsByDetectionId.Values
                .Where(item => !existing.ItemsByDetectionId.ContainsKey(item.DetectionId))
                .ToArray();

            if (missingItems.Length == 0)
            {
                logger.LogInformation("Legacy effectiveness cache migration skipped because SQLite already contains all items.");
                return;
            }

            await store.UpsertManyAsync(missingItems, legacy.Meta, cancellationToken);
            logger.LogInformation("Legacy effectiveness cache migrated. ItemCount={MigratedItemCount}", missingItems.Length);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Legacy effectiveness cache migration failed. The original JSON file was preserved.");
        }
    }

    private static string ResolvePath(string configuredPath)
    {
        return Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), configuredPath));
    }
}

