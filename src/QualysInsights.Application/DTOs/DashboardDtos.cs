namespace QualysInsights.Application.DTOs;

public sealed class DashboardSeverityDistributionDto
{
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public int Info { get; set; }
}

public sealed class DashboardTopVulnerabilityDto
{
    public string Qid { get; set; } = "";
    public int Count { get; set; }
}

public sealed class DashboardSeverityGroupDto
{
    public int Abertas { get; set; }
    public int Corrigidas { get; set; }
}

public sealed class DashboardTagDistributionDto
{
    public DashboardSeverityGroupDto Critical { get; set; } = new();
    public DashboardSeverityGroupDto High { get; set; } = new();
    public DashboardSeverityGroupDto Medium { get; set; } = new();
    public int Total { get; set; }
}

public sealed class DashboardSummaryDto
{
    public int TotalHosts { get; set; }
    public int TotalVulnerabilities { get; set; }
    public DashboardSeverityDistributionDto SeverityDistribution { get; set; } = new();
    public Dictionary<string, int> StatusDistribution { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public IReadOnlyList<DashboardTopVulnerabilityDto> TopVulnerabilities { get; set; } = Array.Empty<DashboardTopVulnerabilityDto>();
    public Dictionary<string, DashboardTagDistributionDto> TagDistribution { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public string LastUpdated { get; set; } = "";
}

public sealed class TrendPointDto
{
    public string Date { get; set; } = "";
    public int Count { get; set; }
}

public sealed class DashboardTrendsDto
{
    public IReadOnlyList<TrendPointDto> Trends { get; set; } = Array.Empty<TrendPointDto>();
    public int TotalDays { get; set; }
}

