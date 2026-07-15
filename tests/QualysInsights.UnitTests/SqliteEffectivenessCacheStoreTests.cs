using Microsoft.EntityFrameworkCore;
using QualysInsights.Application.DTOs;
using QualysInsights.Infrastructure.Persistence;

namespace QualysInsights.UnitTests;

public sealed class SqliteEffectivenessCacheStoreTests
{
    [Fact]
    public async Task UpsertMany_PersistsAndMergesItems()
    {
        await using var db = CreateDbContext();
        await db.Database.MigrateAsync();
        var store = new SqliteEffectivenessCacheStore(db);

        await store.UpsertManyAsync([
            new EffectivenessItemDto
            {
                DetectionId = "123",
                Status = "open",
                Dns = "srv.local",
                Ip = "10.0.0.1",
                Severity = "Alta",
                HostTags = ["PRD"]
            }
        ], new EffectivenessCacheMetaDto { GeneratedAt = "2026-07-15T00:00:00Z" }, CancellationToken.None);

        await store.UpsertManyAsync([
            new EffectivenessItemDto { DetectionId = "123", Status = "fixed", HostTags = [] }
        ], new EffectivenessCacheMetaDto { GeneratedAt = "2026-07-16T00:00:00Z" }, CancellationToken.None);

        var cache = await store.LoadAsync(CancellationToken.None);
        Assert.Equal("fixed", cache.ItemsByDetectionId["123"].Status);
        Assert.Equal("srv.local", cache.ItemsByDetectionId["123"].Dns);
        Assert.Empty(cache.ItemsByDetectionId["123"].HostTags);
        Assert.Equal("2026-07-16T00:00:00Z", cache.Meta.GeneratedAt);
    }

    private static QualysInsightsDbContext CreateDbContext()
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.db");
        var options = new DbContextOptionsBuilder<QualysInsightsDbContext>()
            .UseSqlite($"Data Source={path}")
            .Options;
        return new QualysInsightsDbContext(options);
    }
}

