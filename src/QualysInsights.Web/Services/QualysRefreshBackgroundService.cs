using Microsoft.Extensions.Options;
using QualysInsights.Application.Interfaces;
using QualysInsights.Application.Options;

namespace QualysInsights.Web.Services;

public sealed class QualysRefreshBackgroundService(
    IServiceScopeFactory scopeFactory,
    IOptions<BackgroundRefreshOptions> options,
    ILogger<QualysRefreshBackgroundService> logger) : BackgroundService
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled)
        {
            logger.LogInformation("Background refresh disabled.");
            return;
        }

        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(Math.Max(1, options.Value.IntervalMinutes)));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            if (!await _gate.WaitAsync(0, stoppingToken))
            {
                logger.LogInformation("Background refresh skipped because previous execution is still running.");
                continue;
            }

            try
            {
                var started = DateTimeOffset.UtcNow;
                using var scope = scopeFactory.CreateScope();
                var service = scope.ServiceProvider.GetRequiredService<IQualysDataService>();
                await service.GetHostsAsync(stoppingToken);
                await service.GetVulnerabilitiesAsync(stoppingToken);
                logger.LogInformation("Background refresh completed. DurationMs={DurationMs}", (DateTimeOffset.UtcNow - started).TotalMilliseconds);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Background refresh failed.");
            }
            finally
            {
                _gate.Release();
            }
        }
    }
}

