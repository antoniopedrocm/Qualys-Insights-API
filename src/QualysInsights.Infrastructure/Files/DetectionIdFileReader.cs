using Microsoft.Extensions.Options;
using QualysInsights.Application.Interfaces;
using QualysInsights.Application.Options;

namespace QualysInsights.Infrastructure.Files;

public sealed class DetectionIdFileReader(IOptions<StorageOptions> storageOptions) : IDetectionIdFileReader
{
    public async Task<IReadOnlyList<string>> ReadDetectionIdsAsync(CancellationToken cancellationToken)
    {
        var path = ResolvePath(storageOptions.Value.DetectionIdsCsvPath);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("Arquivo detection_ids.csv não encontrado.", path);
        }

        var lines = await File.ReadAllLinesAsync(path, cancellationToken);
        var normalized = lines
            .Select(line => line.Trim().Replace("\"", "", StringComparison.Ordinal))
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .ToArray();

        if (normalized.Length == 0)
        {
            throw new InvalidOperationException("Arquivo detection_ids.csv está vazio.");
        }

        var candidates = normalized.Length > 0 && !normalized[0].All(char.IsDigit)
            ? normalized.Skip(1)
            : normalized;

        var detectionIds = candidates.Where(id => id.All(char.IsDigit)).Distinct(StringComparer.Ordinal).ToArray();
        if (detectionIds.Length == 0)
        {
            throw new InvalidOperationException("Nenhum Detection ID válido encontrado no arquivo detection_ids.csv.");
        }

        return detectionIds;
    }

    private static string ResolvePath(string configuredPath)
    {
        return Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), configuredPath));
    }
}

