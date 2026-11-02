using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SentinelAI.Infrastructure;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations;

[DbContext(typeof(AppDbContext))]
[Migration("20261102160000_Phase21AssetObservationSemantics")]
public partial class Phase21AssetObservationSemantics : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.RenameColumn(
            name: "LastSeenAt",
            table: "Assets",
            newName: "LastObservedAt");

        migrationBuilder.AddColumn<DateTimeOffset>(
            name: "LastSuccessfulReachabilityAt",
            table: "Assets",
            type: "timestamp with time zone",
            nullable: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(
            name: "LastSuccessfulReachabilityAt",
            table: "Assets");

        migrationBuilder.RenameColumn(
            name: "LastObservedAt",
            table: "Assets",
            newName: "LastSeenAt");
    }
}
