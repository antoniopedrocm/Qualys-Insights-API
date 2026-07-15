using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using QualysInsights.Application.Interfaces;

namespace QualysInsights.IntegrationTests;

public sealed class QualysWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly string _dataDirectory = Path.Combine(Path.GetTempPath(), $"qualys-insights-tests-{Guid.NewGuid():N}");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Qualys:Username"] = "test-user",
                ["Qualys:Password"] = "test-password",
                ["Authentication:Mode"] = "Disabled",
                ["Storage:DataDirectory"] = _dataDirectory,
                ["Storage:LegacyEffectivenessCachePath"] = Path.Combine(_dataDirectory, "missing.json"),
                ["Storage:DetectionIdsCsvPath"] = Path.Combine(_dataDirectory, "detection_ids.csv")
            });
        });

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<IQualysClient>();
            services.AddSingleton<IQualysClient, FakeQualysClient>();
        });
    }
}

