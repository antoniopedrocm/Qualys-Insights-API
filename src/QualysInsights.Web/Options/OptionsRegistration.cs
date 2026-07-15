using QualysInsights.Application.Options;

namespace QualysInsights.Web.Services;

public static class OptionsRegistration
{
    public static IServiceCollection AddConfiguredOptions(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<QualysOptions>()
            .Bind(configuration.GetSection(QualysOptions.SectionName))
            .Validate(options => Uri.TryCreate(options.BaseUrl, UriKind.Absolute, out _), "Qualys:BaseUrl must be an absolute URL.")
            .Validate(options => !string.IsNullOrWhiteSpace(options.Username), "Qualys:Username is required.")
            .Validate(options => !string.IsNullOrWhiteSpace(options.Password), "Qualys:Password is required.")
            .ValidateOnStart();

        services.AddOptions<CacheOptions>()
            .Bind(configuration.GetSection(CacheOptions.SectionName))
            .Validate(options => options.DefaultTtlSeconds > 0, "Cache:DefaultTtlSeconds must be greater than zero.")
            .ValidateOnStart();

        services.AddOptions<StorageOptions>()
            .Bind(configuration.GetSection(StorageOptions.SectionName))
            .Validate(options => !string.IsNullOrWhiteSpace(options.DataDirectory), "Storage:DataDirectory is required.")
            .ValidateOnStart();

        services.AddOptions<AppAuthenticationOptions>()
            .Bind(configuration.GetSection(AppAuthenticationOptions.SectionName))
            .Validate(options => IsValidMode(options.Mode), "Authentication:Mode must be Windows, ApiKey, or Disabled.")
            .Validate(options => !options.Mode.Equals("ApiKey", StringComparison.OrdinalIgnoreCase) || !string.IsNullOrWhiteSpace(options.ApiKeySha256), "Authentication:ApiKeySha256 is required when ApiKey mode is enabled.")
            .ValidateOnStart();

        services.AddOptions<ExportOptions>().Bind(configuration.GetSection(ExportOptions.SectionName)).ValidateOnStart();
        services.AddOptions<RateLimitOptions>().Bind(configuration.GetSection(RateLimitOptions.SectionName)).ValidateOnStart();
        services.AddOptions<SecurityHeadersOptions>().Bind(configuration.GetSection(SecurityHeadersOptions.SectionName)).ValidateOnStart();
        services.AddOptions<HostingOptions>().Bind(configuration.GetSection(HostingOptions.SectionName)).ValidateOnStart();
        services.AddOptions<BackgroundRefreshOptions>().Bind(configuration.GetSection(BackgroundRefreshOptions.SectionName)).ValidateOnStart();
        services.AddOptions<CorsPolicyOptions>().Bind(configuration.GetSection(CorsPolicyOptions.SectionName)).ValidateOnStart();

        return services;
    }

    private static bool IsValidMode(string mode)
    {
        return mode.Equals("Windows", StringComparison.OrdinalIgnoreCase)
            || mode.Equals("ApiKey", StringComparison.OrdinalIgnoreCase)
            || mode.Equals("Disabled", StringComparison.OrdinalIgnoreCase);
    }
}

