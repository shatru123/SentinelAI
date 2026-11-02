using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SentinelAI.Infrastructure;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations;

[DbContext(typeof(AppDbContext))]
[Migration("20261102150000_Phase2PassiveInventory")]
public partial class Phase2PassiveInventory : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "AssetServices",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                AssetId = table.Column<Guid>(type: "uuid", nullable: false),
                Protocol = table.Column<string>(type: "text", nullable: false),
                Port = table.Column<int>(type: "integer", nullable: false),
                Name = table.Column<string>(type: "text", nullable: true),
                Version = table.Column<string>(type: "text", nullable: true),
                ObservedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AssetServices", x => x.Id);
            });

        migrationBuilder.CreateIndex(
            name: "IX_AssetServices_TenantId_AssetId_Protocol_Port",
            table: "AssetServices",
            columns: new[] { "TenantId", "AssetId", "Protocol", "Port" },
            unique: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "AssetServices");
    }
}
