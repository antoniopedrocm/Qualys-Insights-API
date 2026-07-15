using System.ComponentModel.DataAnnotations;

namespace QualysInsights.Application.Options;

public sealed class QualysOptions
{
    public const string SectionName = "Qualys";

    [Required]
    public string BaseUrl { get; set; } = "https://qualysguard.qg3.apps.qualys.com";

    [Required]
    public string Username { get; set; } = "";

    [Required]
    public string Password { get; set; } = "";

    [Range(5, 600)]
    public int TimeoutSeconds { get; set; } = 120;

    [Range(1, 20)]
    public int MaxKnowledgeBaseConcurrency { get; set; } = 3;

    [Range(1, 200)]
    public int KnowledgeBaseBatchSize { get; set; } = 30;

    [Range(0, 10)]
    public int MaxTransientRetries { get; set; } = 3;
}

