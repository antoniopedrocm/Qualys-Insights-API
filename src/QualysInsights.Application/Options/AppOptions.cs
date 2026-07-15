using System.ComponentModel.DataAnnotations;

namespace QualysInsights.Application.Options;

public sealed class CacheOptions
{
    public const string SectionName = "Cache";

    [Range(1, 86400)]
    public int DefaultTtlSeconds { get; set; } = 300;

    public bool AllowStaleOnFailure { get; set; } = true;
}

public sealed class StorageOptions
{
    public const string SectionName = "Storage";

    [Required]
    public string DataDirectory { get; set; } = @"C:\ProgramData\QualysInsights";

    public string DatabaseFileName { get; set; } = "qualys-insights.db";
    public string LegacyEffectivenessCachePath { get; set; } = "data/effectiveness-cache.json";
    public bool MigrateLegacyJsonOnStartup { get; set; } = true;
    public string DetectionIdsCsvPath { get; set; } = "legacy-node/detection_ids.csv";
}

public sealed class AppAuthenticationOptions
{
    public const string SectionName = "Authentication";

    public string Mode { get; set; } = "Windows";
    public IReadOnlyList<string> AllowedActiveDirectoryGroups { get; set; } = Array.Empty<string>();
    public string ApiKeySha256 { get; set; } = "";
}

public sealed class ExportOptions
{
    public const string SectionName = "Export";

    public int MaxRows { get; set; } = 250000;
}

public sealed class RateLimitOptions
{
    public const string SectionName = "RateLimit";

    public int PermitLimit { get; set; } = 20;
    public int WindowSeconds { get; set; } = 60;
}

public sealed class SecurityHeadersOptions
{
    public const string SectionName = "SecurityHeaders";

    public string ContentSecurityPolicy { get; set; } =
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
}

public sealed class HostingOptions
{
    public const string SectionName = "Hosting";

    public string PathBase { get; set; } = "";
    public long MaxRequestBodyBytes { get; set; } = 1_048_576;
}

public sealed class BackgroundRefreshOptions
{
    public const string SectionName = "BackgroundRefresh";

    public bool Enabled { get; set; }
    public int IntervalMinutes { get; set; } = 30;
}

public sealed class CorsPolicyOptions
{
    public const string SectionName = "Cors";

    public IReadOnlyList<string> AllowedOrigins { get; set; } = Array.Empty<string>();
}

