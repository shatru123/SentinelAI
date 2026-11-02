using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class Phase311SecurityHardening : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ApprovedPrivateNetworkRanges",
                table: "Workers",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<bool>(
                name: "PrivateAssessmentApproved",
                table: "Workers",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "ApprovedPrivateNetworkRanges",
                table: "TargetScopes",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "IdempotencyKey",
                table: "Findings",
                type: "text",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "WebAssessmentChecks",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    AssessmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    CheckId = table.Column<string>(type: "text", nullable: false),
                    Name = table.Column<string>(type: "text", nullable: false),
                    Category = table.Column<string>(type: "text", nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    StartedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    CompletedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    AffectedEndpoint = table.Column<string>(type: "text", nullable: true),
                    Reason = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebAssessmentChecks", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Findings_TenantId_AssessmentId_IdempotencyKey",
                table: "Findings",
                columns: new[] { "TenantId", "AssessmentId", "IdempotencyKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_WebAssessmentChecks_TenantId_AssessmentId_CheckId_AffectedE~",
                table: "WebAssessmentChecks",
                columns: new[] { "TenantId", "AssessmentId", "CheckId", "AffectedEndpoint" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "WebAssessmentChecks");

            migrationBuilder.DropIndex(
                name: "IX_Findings_TenantId_AssessmentId_IdempotencyKey",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "ApprovedPrivateNetworkRanges",
                table: "Workers");

            migrationBuilder.DropColumn(
                name: "PrivateAssessmentApproved",
                table: "Workers");

            migrationBuilder.DropColumn(
                name: "ApprovedPrivateNetworkRanges",
                table: "TargetScopes");

            migrationBuilder.DropColumn(
                name: "IdempotencyKey",
                table: "Findings");
        }
    }
}
