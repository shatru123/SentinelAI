using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class Phase121LeasesAndDispatcher : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_OutboxMessages_DispatchedAt_CreatedAt",
                table: "OutboxMessages");

            migrationBuilder.AddColumn<int>(
                name: "CurrentActiveJobs",
                table: "Workers",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LastJobCompletedAt",
                table: "Workers",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LastJobStartedAt",
                table: "Workers",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "MaximumCapacity",
                table: "Workers",
                type: "integer",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddColumn<bool>(
                name: "AllowSubdomains",
                table: "TargetScopes",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LeaseAcquiredAt",
                table: "OutboxMessages",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LeaseExpiresAt",
                table: "OutboxMessages",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LeaseOwner",
                table: "OutboxMessages",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "NextAttemptAt",
                table: "OutboxMessages",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LastLeaseHeartbeatAt",
                table: "AgentJobs",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LeaseAcquiredAt",
                table: "AgentJobs",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LeaseExpiresAt",
                table: "AgentJobs",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LeaseOwnerWorkerId",
                table: "AgentJobs",
                type: "text",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_OutboxMessages_DispatchedAt_NextAttemptAt_LeaseExpiresAt_Cr~",
                table: "OutboxMessages",
                columns: new[] { "DispatchedAt", "NextAttemptAt", "LeaseExpiresAt", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_AgentJobs_Status_LeaseExpiresAt",
                table: "AgentJobs",
                columns: new[] { "Status", "LeaseExpiresAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_OutboxMessages_DispatchedAt_NextAttemptAt_LeaseExpiresAt_Cr~",
                table: "OutboxMessages");

            migrationBuilder.DropIndex(
                name: "IX_AgentJobs_Status_LeaseExpiresAt",
                table: "AgentJobs");

            migrationBuilder.DropColumn(
                name: "CurrentActiveJobs",
                table: "Workers");

            migrationBuilder.DropColumn(
                name: "LastJobCompletedAt",
                table: "Workers");

            migrationBuilder.DropColumn(
                name: "LastJobStartedAt",
                table: "Workers");

            migrationBuilder.DropColumn(
                name: "MaximumCapacity",
                table: "Workers");

            migrationBuilder.DropColumn(
                name: "AllowSubdomains",
                table: "TargetScopes");

            migrationBuilder.DropColumn(
                name: "LeaseAcquiredAt",
                table: "OutboxMessages");

            migrationBuilder.DropColumn(
                name: "LeaseExpiresAt",
                table: "OutboxMessages");

            migrationBuilder.DropColumn(
                name: "LeaseOwner",
                table: "OutboxMessages");

            migrationBuilder.DropColumn(
                name: "NextAttemptAt",
                table: "OutboxMessages");

            migrationBuilder.DropColumn(
                name: "LastLeaseHeartbeatAt",
                table: "AgentJobs");

            migrationBuilder.DropColumn(
                name: "LeaseAcquiredAt",
                table: "AgentJobs");

            migrationBuilder.DropColumn(
                name: "LeaseExpiresAt",
                table: "AgentJobs");

            migrationBuilder.DropColumn(
                name: "LeaseOwnerWorkerId",
                table: "AgentJobs");

            migrationBuilder.CreateIndex(
                name: "IX_OutboxMessages_DispatchedAt_CreatedAt",
                table: "OutboxMessages",
                columns: new[] { "DispatchedAt", "CreatedAt" });
        }
    }
}
