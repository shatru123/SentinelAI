using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SentinelAI.Infrastructure;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations;

[DbContext(typeof(AppDbContext))]
[Migration("20261102171000_Phase211AssetServiceTenantIntegrity")]
public partial class Phase211AssetServiceTenantIntegrity : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1
                    FROM "AssetServices" service
                    LEFT JOIN "Assets" asset
                      ON asset."TenantId" = service."TenantId"
                     AND asset."Id" = service."AssetId"
                    WHERE asset."Id" IS NULL
                ) THEN
                    RAISE EXCEPTION 'AssetServices contains tenant-inconsistent or orphaned asset references';
                END IF;
            END $$;
            """);

        migrationBuilder.AddUniqueConstraint(
            name: "AK_Assets_TenantId_Id",
            table: "Assets",
            columns: new[] { "TenantId", "Id" });

        migrationBuilder.AddForeignKey(
            name: "FK_AssetServices_Assets_TenantId_AssetId",
            table: "AssetServices",
            columns: new[] { "TenantId", "AssetId" },
            principalTable: "Assets",
            principalColumns: new[] { "TenantId", "Id" },
            onDelete: ReferentialAction.Cascade);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropForeignKey(
            name: "FK_AssetServices_Assets_TenantId_AssetId",
            table: "AssetServices");

        migrationBuilder.DropUniqueConstraint(
            name: "AK_Assets_TenantId_Id",
            table: "Assets");
    }
}
