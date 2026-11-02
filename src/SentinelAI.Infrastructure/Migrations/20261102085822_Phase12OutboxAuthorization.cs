using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class Phase12OutboxAuthorization : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AssignedWorkerIdentity",
                table: "AgentJobs",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "CancellationRequestedAt",
                table: "AgentJobs",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "OutboxMessages",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    MessageType = table.Column<string>(type: "text", nullable: false),
                    Payload = table.Column<string>(type: "text", nullable: false),
                    AttemptCount = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    DispatchedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastAttemptAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastError = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OutboxMessages", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PublicTargetAuthorizations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    Target = table.Column<string>(type: "text", nullable: false),
                    RequestedBy = table.Column<Guid>(type: "uuid", nullable: false),
                    Reason = table.Column<string>(type: "text", nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    Evidence = table.Column<string>(type: "text", nullable: true),
                    VerificationMethod = table.Column<string>(type: "text", nullable: true),
                    ApprovedBy = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ApprovedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RevokedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PublicTargetAuthorizations", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_OutboxMessages_DispatchedAt_CreatedAt",
                table: "OutboxMessages",
                columns: new[] { "DispatchedAt", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_PublicTargetAuthorizations_TenantId_Target_Status",
                table: "PublicTargetAuthorizations",
                columns: new[] { "TenantId", "Target", "Status" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "OutboxMessages");

            migrationBuilder.DropTable(
                name: "PublicTargetAuthorizations");

            migrationBuilder.DropColumn(
                name: "AssignedWorkerIdentity",
                table: "AgentJobs");

            migrationBuilder.DropColumn(
                name: "CancellationRequestedAt",
                table: "AgentJobs");
        }
    }
}
