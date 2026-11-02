using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class Phase311AssessmentBudgets : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "MaxConcurrentRequests",
                table: "TargetScopes",
                type: "integer",
                nullable: false,
                defaultValue: 4);

            migrationBuilder.AddColumn<int>(
                name: "MaxCrawlDepth",
                table: "TargetScopes",
                type: "integer",
                nullable: false,
                defaultValue: 2);

            migrationBuilder.AddColumn<int>(
                name: "MaxPages",
                table: "TargetScopes",
                type: "integer",
                nullable: false,
                defaultValue: 24);

            migrationBuilder.AddColumn<int>(
                name: "MaxResponseBytes",
                table: "TargetScopes",
                type: "integer",
                nullable: false,
                defaultValue: 524288);

            migrationBuilder.AddColumn<int>(
                name: "MaxTotalRequests",
                table: "TargetScopes",
                type: "integer",
                nullable: false,
                defaultValue: 200);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "MaxConcurrentRequests",
                table: "TargetScopes");

            migrationBuilder.DropColumn(
                name: "MaxCrawlDepth",
                table: "TargetScopes");

            migrationBuilder.DropColumn(
                name: "MaxPages",
                table: "TargetScopes");

            migrationBuilder.DropColumn(
                name: "MaxResponseBytes",
                table: "TargetScopes");

            migrationBuilder.DropColumn(
                name: "MaxTotalRequests",
                table: "TargetScopes");
        }
    }
}
