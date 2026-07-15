using QualysInsights.Application.DTOs;
using QualysInsights.Application.Interfaces;
using QualysInsights.Application.Models;

namespace QualysInsights.Application.Services;

public sealed class QualysDataService(
    IQualysClient qualysClient,
    ICachedDataProvider cache,
    IEffectivenessCacheStore effectivenessCache,
    IDetectionIdFileReader detectionIdFileReader) : IQualysDataService
{
    public Task<CacheResult<IReadOnlyList<HostDto>>> GetHostsAsync(CancellationToken cancellationToken)
    {
        return cache.GetAsync("hosts", qualysClient.GetHostListAsync, cancellationToken);
    }

    public Task<CacheResult<IReadOnlyList<VulnerabilityDto>>> GetVulnerabilitiesAsync(CancellationToken cancellationToken)
    {
        return cache.GetAsync("vulnerabilities", qualysClient.GetVulnerabilitiesAsync, cancellationToken);
    }

    public Task<IReadOnlyList<ScanDto>> GetScansAsync(CancellationToken cancellationToken)
    {
        return qualysClient.GetScanListAsync(cancellationToken);
    }

    public async Task<CacheResult<DashboardSummaryDto>> GetDashboardSummaryAsync(CancellationToken cancellationToken)
    {
        var vulnerabilitiesResult = await GetVulnerabilitiesAsync(cancellationToken);
        var hostsResult = await GetHostsAsync(cancellationToken);
        var vulnerabilities = vulnerabilitiesResult.Data.Where(vuln => IsRelevantSeverity(vuln.Severity)).ToArray();

        var severityCount = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["1"] = 0,
            ["2"] = 0,
            ["3"] = 0,
            ["4"] = 0,
            ["5"] = 0
        };
        var qidCount = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var statusCount = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var tagDistribution = CreateTagDistribution();

        foreach (var vuln in vulnerabilities)
        {
            var severityKey = SeverityKey(vuln.Severity);
            var normalizedSeverity = severityKey switch
            {
                "critical" => "5",
                "high" => "4",
                _ => "3"
            };
            severityCount[normalizedSeverity]++;

            Increment(qidCount, string.IsNullOrWhiteSpace(vuln.Qid) ? "Unknown" : vuln.Qid);
            Increment(statusCount, string.IsNullOrWhiteSpace(BusinessClassifiers.GetDetectionStatusValue(vuln)) ? "Unknown" : BusinessClassifiers.GetDetectionStatusValue(vuln));

            if (!string.IsNullOrWhiteSpace(vuln.HostTags))
            {
                var tags = BusinessClassifiers.NormalizeTagString(vuln.HostTags);
                var statusBucket = BusinessClassifiers.IsDetectionFixed(vuln) || vuln.IsFixed ? "corrigidas" : "abertas";
                ApplyTagDistribution(tagDistribution, tags, severityKey, statusBucket);
            }
        }

        var summary = new DashboardSummaryDto
        {
            TotalHosts = hostsResult.Data.Count,
            TotalVulnerabilities = vulnerabilities.Length,
            SeverityDistribution = new DashboardSeverityDistributionDto
            {
                Critical = severityCount["5"],
                High = severityCount["4"],
                Medium = severityCount["3"],
                Low = severityCount["2"],
                Info = severityCount["1"]
            },
            StatusDistribution = statusCount,
            TopVulnerabilities = qidCount
                .OrderByDescending(item => item.Value)
                .Take(10)
                .Select(item => new DashboardTopVulnerabilityDto { Qid = item.Key, Count = item.Value })
                .ToArray(),
            TagDistribution = tagDistribution,
            LastUpdated = DateTimeOffset.UtcNow.ToString("O")
        };

        return new CacheResult<DashboardSummaryDto>
        {
            Data = summary,
            Cached = vulnerabilitiesResult.Cached || hostsResult.Cached,
            Stale = vulnerabilitiesResult.Stale || hostsResult.Stale,
            Error = vulnerabilitiesResult.Error ?? hostsResult.Error
        };
    }

    public async Task<CacheResult<DashboardTrendsDto>> GetDashboardTrendsAsync(CancellationToken cancellationToken)
    {
        var vulnerabilitiesResult = await GetVulnerabilitiesAsync(cancellationToken);
        var trends = vulnerabilitiesResult.Data
            .Where(vuln => IsRelevantSeverity(vuln.Severity) && !string.IsNullOrWhiteSpace(vuln.FirstFound))
            .GroupBy(vuln => vuln.FirstFound.Split('T')[0])
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => new TrendPointDto { Date = group.Key, Count = group.Count() })
            .ToArray();

        return new CacheResult<DashboardTrendsDto>
        {
            Data = new DashboardTrendsDto { Trends = trends, TotalDays = trends.Length },
            Cached = vulnerabilitiesResult.Cached,
            Stale = vulnerabilitiesResult.Stale,
            Error = vulnerabilitiesResult.Error
        };
    }

    public async Task<EffectivenessResponse> AnalyzeEffectivenessAsync(IReadOnlyList<string> detectionIds, CancellationToken cancellationToken)
    {
        var uniqueIds = detectionIds.Select(id => id.Trim()).Where(id => id.Length > 0).Distinct(StringComparer.Ordinal).ToArray();
        var vulnResult = await GetVulnerabilitiesAsync(cancellationToken);
        var vulnerabilitiesById = vulnResult.Data
            .Select(vuln => new { Id = FirstNonEmpty(vuln.DetectionId, vuln.UniqueVulnId), Vuln = vuln })
            .Where(item => !string.IsNullOrWhiteSpace(item.Id))
            .GroupBy(item => item.Id, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First().Vuln, StringComparer.Ordinal);

        var activeSet = vulnerabilitiesById
            .Where(item => !BusinessClassifiers.IsDetectionFixed(item.Value) && !item.Value.IsFixed)
            .Select(item => item.Key)
            .ToHashSet(StringComparer.Ordinal);

        var classified = DetectionIdClassifier.Classify(uniqueIds, activeSet);
        var generatedAt = DateTimeOffset.UtcNow.ToString("O");
        var existingCache = await effectivenessCache.LoadAsync(cancellationToken);
        var itemsToPersist = classified.Items.Select(item =>
        {
            existingCache.ItemsByDetectionId.TryGetValue(item.DetectionId, out var existingItem);
            vulnerabilitiesById.TryGetValue(item.DetectionId, out var vuln);
            return BuildEffectivenessItem(item, vuln, existingItem, generatedAt);
        }).ToArray();

        var persisted = await effectivenessCache.UpsertManyAsync(
            itemsToPersist,
            new EffectivenessCacheMetaDto { GeneratedAt = generatedAt, Source = "qualys-active-vulns-cache", Version = 1 },
            cancellationToken);

        return new EffectivenessResponse
        {
            Total = classified.Total,
            Fixed = classified.Fixed,
            Open = classified.Open,
            Invalid = classified.Invalid,
            Cached = vulnResult.Cached,
            Stale = vulnResult.Stale,
            Filters = new EffectivenessFiltersDto
            {
                Severities = itemsToPersist.Select(item => item.Severity).Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                HostTags = itemsToPersist.SelectMany(item => item.HostTags).Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
            },
            Items = classified.Items.Select(item => persisted.ItemsByDetectionId.TryGetValue(item.DetectionId, out var cacheItem)
                ? cacheItem
                : new EffectivenessItemDto { DetectionId = item.DetectionId, Status = item.Status }).ToArray()
        };
    }

    public Task<EffectivenessCacheDto> GetEffectivenessCacheAsync(CancellationToken cancellationToken)
    {
        return effectivenessCache.LoadAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<DetectionDto>> GetEnrichedDetectionsAsync(CancellationToken cancellationToken)
    {
        var detections = await qualysClient.GetHostDetectionsWithDetailsAsync(cancellationToken);
        return detections.Select(detection =>
        {
            detection.Priority = BusinessClassifiers.CalculatePriority(detection);
            detection.OwnerArea = BusinessClassifiers.ClassifyOwner(detection);
            detection.Environment = BusinessClassifiers.ClassifyEnvironment(detection);
            return detection;
        }).ToArray();
    }

    public async Task<(LegacyEffectivenessSummaryDto Summary, IReadOnlyList<DetectionDto> Detections, IReadOnlyList<string> AttemptedIds)> CalculateLegacyEffectivenessAsync(CancellationToken cancellationToken)
    {
        var detectionIds = await detectionIdFileReader.ReadDetectionIdsAsync(cancellationToken);
        var tasks = detectionIds.Select(id => qualysClient.GetDetectionByIdAsync(id, cancellationToken)).ToArray();
        var detections = (await Task.WhenAll(tasks)).Where(detection => detection is not null).Cast<DetectionDto>().ToArray();

        return (BuildLegacyEffectivenessSummary(detections), detections, detectionIds);
    }

    private static EffectivenessItemDto BuildEffectivenessItem(DetectionIdClassification item, VulnerabilityDto? vuln, EffectivenessItemDto? existingItem, string generatedAt)
    {
        if (item.Status == "invalid")
        {
            return new EffectivenessItemDto
            {
                DetectionId = item.DetectionId,
                Status = "invalid",
                Dns = existingItem?.Dns ?? "",
                Ip = existingItem?.Ip ?? "",
                Title = existingItem?.Title ?? "",
                Severity = existingItem?.Severity ?? "Info",
                Solution = existingItem?.Solution ?? "",
                HostTags = existingItem?.HostTags ?? Array.Empty<string>(),
                LastSeen = null
            };
        }

        if (item.Status == "fixed")
        {
            return new EffectivenessItemDto
            {
                DetectionId = item.DetectionId,
                Status = "fixed",
                Dns = FirstNonEmpty(existingItem?.Dns, vuln?.HostDns),
                Ip = FirstNonEmpty(existingItem?.Ip, vuln?.HostIp),
                Title = FirstNonEmpty(existingItem?.Title, vuln?.Title),
                Severity = FirstNonEmpty(existingItem?.Severity, SeverityNormalizer.Normalize(vuln?.Severity)),
                Solution = FirstNonEmpty(existingItem?.Solution, vuln?.Solution),
                HostTags = existingItem?.HostTags?.Count > 0 ? existingItem.HostTags : BusinessClassifiers.ParseHostTags(vuln?.HostTags),
                LastSeen = ResolveLastSeen(vuln, "fixed", generatedAt, existingItem)
            };
        }

        return new EffectivenessItemDto
        {
            DetectionId = item.DetectionId,
            Status = "open",
            Dns = FirstNonEmpty(vuln?.HostDns, existingItem?.Dns),
            Ip = FirstNonEmpty(vuln?.HostIp, existingItem?.Ip),
            Title = FirstNonEmpty(vuln?.Title, existingItem?.Title),
            Severity = SeverityNormalizer.Normalize(FirstNonEmpty(vuln?.Severity, existingItem?.Severity)),
            Solution = FirstNonEmpty(vuln?.Solution, existingItem?.Solution),
            HostTags = BusinessClassifiers.ParseHostTags(FirstNonEmpty(vuln?.HostTags, existingItem is null ? "" : string.Join(',', existingItem.HostTags))),
            LastSeen = ResolveLastSeen(vuln, "open", generatedAt, existingItem)
        };
    }

    private static string? ResolveLastSeen(VulnerabilityDto? vuln, string status, string generatedAt, EffectivenessItemDto? existingItem)
    {
        var explicitLastSeen = FirstNonEmpty(vuln?.LastSeen, vuln?.LastFound);
        if (!string.IsNullOrWhiteSpace(explicitLastSeen)) return explicitLastSeen;
        if (status == "open") return generatedAt;
        if (status == "fixed") return existingItem?.LastSeen;
        return null;
    }

    private static LegacyEffectivenessSummaryDto BuildLegacyEffectivenessSummary(IReadOnlyList<DetectionDto> detections)
    {
        var summary = new LegacyEffectivenessSummaryDto
        {
            WindowLabels = BusinessClassifiers.DetectionWindowLabels.ToDictionary(item => item.Key, item => item.Value, StringComparer.OrdinalIgnoreCase)
        };

        foreach (var window in BusinessClassifiers.DetectionWindows)
        {
            summary.Windows[window] = new LegacyEffectivenessWindowDto { Label = BusinessClassifiers.DetectionWindowLabels[window] };
        }

        foreach (var detection in detections)
        {
            var window = BusinessClassifiers.ClassifyWindow(detection.HostTags);
            if (window is null || !summary.Windows.TryGetValue(window, out var windowData))
            {
                continue;
            }

            windowData.Total++;
            summary.TotalGeral++;

            if (BusinessClassifiers.IsDetectionFixed(detection))
            {
                windowData.Corrigidas++;
            }
            else
            {
                windowData.Pendentes++;
            }
        }

        foreach (var window in summary.Windows.Values.Where(window => window.Total > 0))
        {
            window.Efetividade = Math.Round((decimal)window.Corrigidas / window.Total, 2);
        }

        return summary;
    }

    private static bool IsRelevantSeverity(string severity)
    {
        return severity is "3" or "4" or "5";
    }

    private static string SeverityKey(string severity)
    {
        var normalized = severity.ToUpperInvariant();
        return normalized switch
        {
            "5" or "CRITICAL" => "critical",
            "4" or "HIGH" => "high",
            _ => "medium"
        };
    }

    private static Dictionary<string, DashboardTagDistributionDto> CreateTagDistribution()
    {
        return new Dictionary<string, DashboardTagDistributionDto>(StringComparer.OrdinalIgnoreCase)
        {
            ["DEV_QA"] = new(),
            ["PRD_Baixa"] = new(),
            ["PRD_Alta"] = new()
        };
    }

    private static void ApplyTagDistribution(Dictionary<string, DashboardTagDistributionDto> tagDistribution, string tags, string severityKey, string statusBucket)
    {
        if (tags.Contains("DEV_QA", StringComparison.OrdinalIgnoreCase)) IncrementSeverity(tagDistribution["DEV_QA"], severityKey, statusBucket);
        if (tags.Contains("PRD_BAIXA", StringComparison.OrdinalIgnoreCase)) IncrementSeverity(tagDistribution["PRD_Baixa"], severityKey, statusBucket);
        if (tags.Contains("PRD_ALTA", StringComparison.OrdinalIgnoreCase)) IncrementSeverity(tagDistribution["PRD_Alta"], severityKey, statusBucket);
    }

    private static void IncrementSeverity(DashboardTagDistributionDto dto, string severityKey, string statusBucket)
    {
        var group = severityKey switch
        {
            "critical" => dto.Critical,
            "high" => dto.High,
            _ => dto.Medium
        };

        if (statusBucket == "corrigidas") group.Corrigidas++;
        else group.Abertas++;

        dto.Total++;
    }

    private static void Increment(IDictionary<string, int> values, string key)
    {
        values[key] = values.TryGetValue(key, out var count) ? count + 1 : 1;
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? "";
    }
}

