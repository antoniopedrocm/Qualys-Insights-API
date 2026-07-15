namespace QualysInsights.Application.DTOs;

public sealed class HostDto
{
    public string Id { get; set; } = "";
    public string Ip { get; set; } = "";
    public string TrackingMethod { get; set; } = "";
    public string Dns { get; set; } = "";
    public string Netbios { get; set; } = "";
    public string Os { get; set; } = "";
    public string LastVulnScan { get; set; } = "";
    public string Tags { get; set; } = "";
}

public sealed class VulnerabilityDto
{
    public string DetectionId { get; set; } = "";
    public string UniqueVulnId { get; set; } = "";
    public string HostId { get; set; } = "";
    public string HostIp { get; set; } = "";
    public string HostDns { get; set; } = "";
    public string HostTags { get; set; } = "";
    public string Os { get; set; } = "";
    public string Qid { get; set; } = "";
    public string Type { get; set; } = "";
    public string TypeDetected { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Status { get; set; } = "";
    public string DetectionStatus { get; set; } = "";
    public string FindingStatus { get; set; } = "";
    public string State { get; set; } = "";
    public bool IsFixed { get; set; }
    public string FirstFound { get; set; } = "";
    public string LastFound { get; set; } = "";
    public string Port { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string Ssl { get; set; } = "";
    public string Title { get; set; } = "";
    public string Solution { get; set; } = "";
    public string Results { get; set; } = "";
    public string LastSeen { get; set; } = "";
}

public sealed class ScanDto
{
    public string Ref { get; set; } = "";
    public string Title { get; set; } = "";
    public string Type { get; set; } = "";
    public string LaunchDate { get; set; } = "";
    public string State { get; set; } = "";
    public string Target { get; set; } = "";
}

public sealed class KnowledgeBaseDetailDto
{
    public string UniqueVulnId { get; set; } = "";
    public string Title { get; set; } = "";
    public string Solution { get; set; } = "";
}

public sealed class DetectionDto
{
    public string DetectionId { get; set; } = "";
    public string UniqueVulnId { get; set; } = "";
    public string HostIp { get; set; } = "";
    public string HostDns { get; set; } = "";
    public string HostTags { get; set; } = "";
    public string Os { get; set; } = "";
    public string Qid { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Status { get; set; } = "";
    public string FirstFound { get; set; } = "";
    public string LastFound { get; set; } = "";
    public string Title { get; set; } = "";
    public string Solution { get; set; } = "";
    public string Host { get; set; } = "";
    public string Priority { get; set; } = "";
    public string OwnerArea { get; set; } = "";
    public string Environment { get; set; } = "";
}

