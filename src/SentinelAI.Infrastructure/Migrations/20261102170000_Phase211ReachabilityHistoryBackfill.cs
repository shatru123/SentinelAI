using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SentinelAI.Infrastructure;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations;

[DbContext(typeof(AppDbContext))]
[Migration("20261102170000_Phase211ReachabilityHistoryBackfill")]
public partial class Phase211ReachabilityHistoryBackfill : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            UPDATE "Assets"
            SET "LastSuccessfulReachabilityAt" = "LastObservedAt"
            WHERE "IsOnline" = TRUE
              AND "LastSuccessfulReachabilityAt" IS NULL;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        // This migration only backfills historical evidence. Keep it intact on rollback;
        // removing a reachability timestamp would destroy audit history.
    }
}
