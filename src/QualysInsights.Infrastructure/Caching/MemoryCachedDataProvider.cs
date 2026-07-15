using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using QualysInsights.Application.Interfaces;
using QualysInsights.Application.Models;
using QualysInsights.Application.Options;

namespace QualysInsights.Infrastructure.Caching;

public sealed class MemoryCachedDataProvider(IOptions<CacheOptions> options, ILogger<MemoryCachedDataProvider> logger) : ICachedDataProvider
{
    private readonly CacheOptions _options = options.Value;
    private readonly ConcurrentDictionary<string, CacheEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new(StringComparer.OrdinalIgnoreCase);

    public async Task<CacheResult<T>> GetAsync<T>(string key, Func<CancellationToken, Task<T>> factory, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        if (_entries.TryGetValue(key, out var existing) && existing.Value is T cached && now - existing.LastUpdate < TimeSpan.FromSeconds(_options.DefaultTtlSeconds))
        {
            logger.LogInformation("Cache hit. Key={CacheKey}", key);
            return new CacheResult<T> { Data = cached, Cached = true };
        }

        var gate = _locks.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        try
        {
            now = DateTimeOffset.UtcNow;
            if (_entries.TryGetValue(key, out existing) && existing.Value is T cachedAfterWait && now - existing.LastUpdate < TimeSpan.FromSeconds(_options.DefaultTtlSeconds))
            {
                logger.LogInformation("Cache hit after wait. Key={CacheKey}", key);
                return new CacheResult<T> { Data = cachedAfterWait, Cached = true };
            }

            try
            {
                logger.LogInformation("Cache miss. Key={CacheKey}", key);
                var data = await factory(cancellationToken);
                _entries[key] = new CacheEntry(data!, DateTimeOffset.UtcNow);
                return new CacheResult<T> { Data = data, Cached = false };
            }
            catch (Exception ex) when (_options.AllowStaleOnFailure && existing?.Value is T stale)
            {
                logger.LogWarning(ex, "Returning stale cache data. Key={CacheKey}", key);
                return new CacheResult<T> { Data = stale, Cached = true, Stale = true, Error = ex };
            }
        }
        finally
        {
            gate.Release();
        }
    }

    private sealed record CacheEntry(object Value, DateTimeOffset LastUpdate);
}

