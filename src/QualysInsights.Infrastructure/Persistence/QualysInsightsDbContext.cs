using Microsoft.EntityFrameworkCore;

namespace QualysInsights.Infrastructure.Persistence;

public sealed class QualysInsightsDbContext(DbContextOptions<QualysInsightsDbContext> options) : DbContext(options)
{
    public DbSet<EffectivenessItemEntity> EffectivenessItems => Set<EffectivenessItemEntity>();
    public DbSet<EffectivenessCacheMetadataEntity> EffectivenessCacheMetadata => Set<EffectivenessCacheMetadataEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<EffectivenessItemEntity>(entity =>
        {
            entity.ToTable("EffectivenessItems");
            entity.HasKey(item => item.DetectionId);
            entity.Property(item => item.DetectionId).HasMaxLength(64);
            entity.Property(item => item.Status).HasMaxLength(32);
            entity.HasIndex(item => item.DetectionId).IsUnique();
        });

        modelBuilder.Entity<EffectivenessCacheMetadataEntity>(entity =>
        {
            entity.ToTable("EffectivenessCacheMetadata");
            entity.HasKey(item => item.Id);
        });
    }
}

