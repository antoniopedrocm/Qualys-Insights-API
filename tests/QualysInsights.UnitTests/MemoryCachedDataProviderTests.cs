using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using QualysInsights.Application.Options;
using QualysInsights.Infrastructure.Caching;

namespace QualysInsights.UnitTests;

public sealed class MemoryCachedDataProviderTests
{
    [Fact]
    public async Task GetAsync_ReturnsCacheHitBeforeTtlExpires()
    {
        var cache = NewCache();
        var calls = 0;

        var first = await cache.GetAsync("key", _ => Task.FromResult(++calls), CancellationToken.None);
        var second = await cache.GetAsync("key", _ => Task.FromResult(++calls), CancellationToken.None);

        Assert.False(first.Cached);
        Assert.True(second.Cached);
        Assert.Equal(1, second.Data);
    }

    [Fact]
    public async Task GetAsync_ReturnsStaleDataWhenRefreshFails()
    {
        var cache = NewCache(ttlSeconds: 1);
        await cache.GetAsync("key", _ => Task.FromResult("fresh"), CancellationToken.None);
        await Task.Delay(1100);

        var stale = await cache.GetAsync<string>("key", _ => throw new InvalidOperationException("offline"), CancellationToken.None);

        Assert.True(stale.Cached);
        Assert.True(stale.Stale);
        Assert.Equal("fresh", stale.Data);
    }

    private static MemoryCachedDataProvider NewCache(int ttlSeconds = 300)
    {
        return new MemoryCachedDataProvider(
            Options.Create(new CacheOptions { DefaultTtlSeconds = ttlSeconds, AllowStaleOnFailure = true }),
            NullLogger<MemoryCachedDataProvider>.Instance);
    }
}

