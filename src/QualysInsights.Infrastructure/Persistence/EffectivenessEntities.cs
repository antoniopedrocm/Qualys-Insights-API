namespace QualysInsights.Infrastructure.Persistence;

public sealed class EffectivenessItemEntity
{
    public string DetectionId { get; set; } = "";
    public string Status { get; set; } = "";
    public string Dns { get; set; } = "";
    public string Ip { get; set; } = "";
    public string Title { get; set; } = "";
    public string Severity { get; set; } = "Info";
    public string Solution { get; set; } = "";
    public string HostTagsJson { get; set; } = "[]";
    public string? LastSeen { get; set; }
    public string UpdatedAt { get; set; } = DateTimeOffset.UtcNow.ToString("O");
}

public sealed class EffectivenessCacheMetadataEntity
{
    public int Id { get; set; }
    public string GeneratedAt { get; set; } = DateTimeOffset.UnixEpoch.ToString("O");
    public string Source { get; set; } = "qualys-active-vulns-cache";
    public int Version { get; set; } = 1;
    public string UpdatedAt { get; set; } = DateTimeOffset.UtcNow.ToString("O");
}

