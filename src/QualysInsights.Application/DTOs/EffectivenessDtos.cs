namespace QualysInsights.Application.DTOs;

public sealed class EffectivenessRequest
{
    public IReadOnlyList<string>? DetectionIds { get; init; }
    public string? Input { get; init; }
}

public sealed class EffectivenessCacheMetaDto
{
    public string GeneratedAt { get; set; } = DateTimeOffset.UnixEpoch.ToString("O");
    public string Source { get; set; } = "qualys-active-vulns-cache";
    public int Version { get; set; } = 1;
}

public sealed class EffectivenessItemDto
{
    public string DetectionId { get; set; } = "";
    public string Status { get; set; } = "";
    public string Dns { get; set; } = "";
    public string Ip { get; set; } = "";
    public string Title { get; set; } = "";
    public string Severity { get; set; } = "Info";
    public string Solution { get; set; } = "";
    public IReadOnlyList<string> HostTags { get; set; } = Array.Empty<string>();
    public string? LastSeen { get; set; }
}

public sealed class EffectivenessCacheDto
{
    public EffectivenessCacheMetaDto Meta { get; set; } = new();
    public Dictionary<string, EffectivenessItemDto> ItemsByDetectionId { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class EffectivenessFiltersDto
{
    public IReadOnlyList<string> Severities { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> HostTags { get; init; } = Array.Empty<string>();
}

public sealed class EffectivenessResponse
{
    public bool Success { get; init; } = true;
    public int Total { get; init; }
    public int Fixed { get; init; }
    public int Open { get; init; }
    public int Invalid { get; init; }
    public bool Cached { get; init; }
    public bool Stale { get; init; }
    public EffectivenessFiltersDto Filters { get; init; } = new();
    public IReadOnlyList<EffectivenessItemDto> Items { get; init; } = Array.Empty<EffectivenessItemDto>();
}

public sealed class LegacyEffectivenessWindowDto
{
    public string Label { get; set; } = "";
    public int Total { get; set; }
    public int Corrigidas { get; set; }
    public int Pendentes { get; set; }
    public decimal Efetividade { get; set; }
}

public sealed class LegacyEffectivenessSummaryDto
{
    public int TotalGeral { get; set; }
    public Dictionary<string, string> WindowLabels { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, LegacyEffectivenessWindowDto> Windows { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

