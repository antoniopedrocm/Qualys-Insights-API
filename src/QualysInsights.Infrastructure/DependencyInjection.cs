using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using QualysInsights.Application.Interfaces;
using QualysInsights.Application.Options;
using QualysInsights.Infrastructure.Caching;
using QualysInsights.Infrastructure.Export;
using QualysInsights.Infrastructure.Files;
using QualysInsights.Infrastructure.Persistence;
using QualysInsights.Infrastructure.Qualys;

namespace QualysInsights.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddQualysInfrastructure(this IServiceCollection services)
    {
        services.AddSingleton<QualysXmlParser>();
        services.AddSingleton<ICachedDataProvider, MemoryCachedDataProvider>();
        services.AddScoped<IEffectivenessCacheStore, SqliteEffectivenessCacheStore>();
        services.AddScoped<ILegacyEffectivenessCacheMigrator, LegacyEffectivenessCacheMigrator>();
        services.AddSingleton<IExportService, SpreadsheetExportService>();
        services.AddSingleton<IDetectionIdFileReader, DetectionIdFileReader>();

        services.AddDbContext<QualysInsightsDbContext>((provider, options) =>
        {
            var storage = provider.GetRequiredService<IOptions<StorageOptions>>().Value;
            Directory.CreateDirectory(storage.DataDirectory);
            var databasePath = Path.Combine(storage.DataDirectory, storage.DatabaseFileName);
            options.UseSqlite($"Data Source={databasePath}");
        });

        services.AddHttpClient<IQualysClient, QualysClient>((provider, client) =>
        {
            var options = provider.GetRequiredService<IOptions<QualysOptions>>().Value;
            client.BaseAddress = new Uri(options.BaseUrl);
            client.Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds);
        });

        return services;
    }
}

