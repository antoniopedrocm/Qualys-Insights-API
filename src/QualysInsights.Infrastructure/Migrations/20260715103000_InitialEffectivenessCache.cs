using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using QualysInsights.Infrastructure.Persistence;

#nullable disable

namespace QualysInsights.Infrastructure.Migrations;

[DbContext(typeof(QualysInsightsDbContext))]
[Migration("20260715103000_InitialEffectivenessCache")]
public partial class InitialEffectivenessCache : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "EffectivenessCacheMetadata",
            columns: table => new
            {
                Id = table.Column<int>(type: "INTEGER", nullable: false)
                    .Annotation("Sqlite:Autoincrement", true),
                GeneratedAt = table.Column<string>(type: "TEXT", nullable: false),
                Source = table.Column<string>(type: "TEXT", nullable: false),
                Version = table.Column<int>(type: "INTEGER", nullable: false),
                UpdatedAt = table.Column<string>(type: "TEXT", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_EffectivenessCacheMetadata", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "EffectivenessItems",
            columns: table => new
            {
                DetectionId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                Status = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                Dns = table.Column<string>(type: "TEXT", nullable: false),
                Ip = table.Column<string>(type: "TEXT", nullable: false),
                Title = table.Column<string>(type: "TEXT", nullable: false),
                Severity = table.Column<string>(type: "TEXT", nullable: false),
                Solution = table.Column<string>(type: "TEXT", nullable: false),
                HostTagsJson = table.Column<string>(type: "TEXT", nullable: false),
                LastSeen = table.Column<string>(type: "TEXT", nullable: true),
                UpdatedAt = table.Column<string>(type: "TEXT", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_EffectivenessItems", x => x.DetectionId);
            });

        migrationBuilder.CreateIndex(
            name: "IX_EffectivenessItems_DetectionId",
            table: "EffectivenessItems",
            column: "DetectionId",
            unique: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "EffectivenessCacheMetadata");
        migrationBuilder.DropTable(name: "EffectivenessItems");
    }
}
