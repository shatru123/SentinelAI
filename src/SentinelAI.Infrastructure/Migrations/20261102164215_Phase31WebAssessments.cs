using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class Phase31WebAssessments : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "PrivateWorkerIdentity",
                table: "TargetScopes",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "WebHostingMode",
                table: "TargetScopes",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AffectedUrl",
                table: "Findings",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "AssessmentId",
                table: "Findings",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Category",
                table: "Findings",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "CheckStatus",
                table: "Findings",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "Confidence",
                table: "Findings",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "HttpMethod",
                table: "Findings",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Impact",
                table: "Findings",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Parameter",
                table: "Findings",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "References",
                table: "Findings",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Remediation",
                table: "Findings",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Reproduction",
                table: "Findings",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ContentType",
                table: "Evidence",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RedactedContent",
                table: "Evidence",
                type: "text",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "AssessmentScreenshots",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    AssessmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    FindingId = table.Column<Guid>(type: "uuid", nullable: true),
                    Url = table.Column<string>(type: "text", nullable: false),
                    ScreenshotType = table.Column<string>(type: "text", nullable: false),
                    Format = table.Column<string>(type: "text", nullable: false),
                    StorageKey = table.Column<string>(type: "text", nullable: false),
                    Sha256 = table.Column<string>(type: "text", nullable: false),
                    CapturedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AssessmentScreenshots", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "WebAssessmentEndpoints",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    AssessmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    Url = table.Column<string>(type: "text", nullable: false),
                    Method = table.Column<string>(type: "text", nullable: false),
                    Depth = table.Column<int>(type: "integer", nullable: false),
                    Kind = table.Column<string>(type: "text", nullable: false),
                    DiscoveredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebAssessmentEndpoints", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "WebAssessments",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    AgentJobId = table.Column<Guid>(type: "uuid", nullable: false),
                    ScopeId = table.Column<Guid>(type: "uuid", nullable: false),
                    TargetUrl = table.Column<string>(type: "text", nullable: false),
                    Profile = table.Column<string>(type: "text", nullable: false),
                    HostingMode = table.Column<int>(type: "integer", nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    StartedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CompletedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    FailureReason = table.Column<string>(type: "text", nullable: true),
                    ReportStorageKey = table.Column<string>(type: "text", nullable: true),
                    DiscoveredEndpointCount = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebAssessments", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AssessmentScreenshots_TenantId_AssessmentId_Id",
                table: "AssessmentScreenshots",
                columns: new[] { "TenantId", "AssessmentId", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_WebAssessmentEndpoints_TenantId_AssessmentId_Url",
                table: "WebAssessmentEndpoints",
                columns: new[] { "TenantId", "AssessmentId", "Url" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_WebAssessments_TenantId_AgentJobId",
                table: "WebAssessments",
                columns: new[] { "TenantId", "AgentJobId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_WebAssessments_TenantId_CreatedAt",
                table: "WebAssessments",
                columns: new[] { "TenantId", "CreatedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AssessmentScreenshots");

            migrationBuilder.DropTable(
                name: "WebAssessmentEndpoints");

            migrationBuilder.DropTable(
                name: "WebAssessments");

            migrationBuilder.DropColumn(
                name: "PrivateWorkerIdentity",
                table: "TargetScopes");

            migrationBuilder.DropColumn(
                name: "WebHostingMode",
                table: "TargetScopes");

            migrationBuilder.DropColumn(
                name: "AffectedUrl",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "AssessmentId",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "Category",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "CheckStatus",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "Confidence",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "HttpMethod",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "Impact",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "Parameter",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "References",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "Remediation",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "Reproduction",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "ContentType",
                table: "Evidence");

            migrationBuilder.DropColumn(
                name: "RedactedContent",
                table: "Evidence");
        }
    }
}
