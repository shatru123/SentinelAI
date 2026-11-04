using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations;

public partial class Phase44ScheduledReassessment : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<Guid>("ResourceId", "Notifications", type: "uuid", nullable: true);
        migrationBuilder.AddColumn<bool>("IsRead", "Notifications", type: "boolean", nullable: false, defaultValue: false);
        migrationBuilder.AddColumn<DateTimeOffset>("ReadAt", "Notifications", type: "timestamp with time zone", nullable: true);
        migrationBuilder.AddColumn<Guid>("ReadBy", "Notifications", type: "uuid", nullable: true);

        migrationBuilder.CreateTable(
            name: "AssessmentSchedules",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                ScopeId = table.Column<Guid>(type: "uuid", nullable: false),
                CreatedBy = table.Column<Guid>(type: "uuid", nullable: false),
                OperationProfile = table.Column<string>(type: "text", nullable: false),
                AuthorizationFingerprint = table.Column<string>(type: "text", nullable: false),
                IntervalHours = table.Column<int>(type: "integer", nullable: false),
                EndsAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                NextRunAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                LastRunAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                LastResult = table.Column<string>(type: "text", nullable: true),
                Status = table.Column<int>(type: "integer", nullable: false),
                BlockedReason = table.Column<string>(type: "text", nullable: true),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                RowVersion = table.Column<byte[]>(type: "bytea", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AssessmentSchedules", x => x.Id);
                table.UniqueConstraint("AK_AssessmentSchedules_TenantId_Id", x => new { x.TenantId, x.Id });
            });

        migrationBuilder.CreateTable(
            name: "AssessmentScheduleRuns",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                ScheduleId = table.Column<Guid>(type: "uuid", nullable: false),
                ScheduledFor = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                IdempotencyKey = table.Column<string>(type: "text", nullable: false),
                Status = table.Column<int>(type: "integer", nullable: false),
                JobId = table.Column<Guid>(type: "uuid", nullable: true),
                AssessmentId = table.Column<Guid>(type: "uuid", nullable: true),
                BlockedReason = table.Column<string>(type: "text", nullable: true),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                CompletedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                ComparedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AssessmentScheduleRuns", x => x.Id);
                table.UniqueConstraint("AK_AssessmentScheduleRuns_TenantId_Id", x => new { x.TenantId, x.Id });
                table.ForeignKey("FK_AssessmentScheduleRuns_AssessmentSchedules_TenantId_ScheduleId",
                    x => new { x.TenantId, x.ScheduleId }, "AssessmentSchedules", new[] { "TenantId", "Id" },
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "AssessmentDriftEvents",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                ScheduleId = table.Column<Guid>(type: "uuid", nullable: false),
                ScheduleRunId = table.Column<Guid>(type: "uuid", nullable: false),
                PreviousAssessmentId = table.Column<Guid>(type: "uuid", nullable: false),
                CurrentAssessmentId = table.Column<Guid>(type: "uuid", nullable: false),
                EventType = table.Column<string>(type: "text", nullable: false),
                StableIdentifier = table.Column<string>(type: "text", nullable: false),
                PreviousSeverity = table.Column<int>(type: "integer", nullable: true),
                CurrentSeverity = table.Column<int>(type: "integer", nullable: true),
                Summary = table.Column<string>(type: "text", nullable: false),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                AcknowledgedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                AcknowledgedBy = table.Column<Guid>(type: "uuid", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_AssessmentDriftEvents", x => x.Id);
                table.UniqueConstraint("AK_AssessmentDriftEvents_TenantId_Id", x => new { x.TenantId, x.Id });
                table.ForeignKey("FK_AssessmentDriftEvents_AssessmentSchedules_TenantId_ScheduleId",
                    x => new { x.TenantId, x.ScheduleId }, "AssessmentSchedules", new[] { "TenantId", "Id" },
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey("FK_AssessmentDriftEvents_AssessmentScheduleRuns_TenantId_ScheduleRunId",
                    x => new { x.TenantId, x.ScheduleRunId }, "AssessmentScheduleRuns", new[] { "TenantId", "Id" },
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex("IX_TargetScopes_TenantId_Id", "TargetScopes",
            new[] { "TenantId", "Id" }, unique: true);
        migrationBuilder.Sql("""
            ALTER TABLE "AssessmentSchedules"
            ADD CONSTRAINT "FK_AssessmentSchedules_TargetScopes_TenantId_ScopeId"
            FOREIGN KEY ("TenantId", "ScopeId")
            REFERENCES "TargetScopes" ("TenantId", "Id")
            ON DELETE RESTRICT;
            """);
        migrationBuilder.CreateIndex("IX_AssessmentDriftEvents_TenantId_ScheduleId", "AssessmentDriftEvents",
            new[] { "TenantId", "ScheduleId" });
        migrationBuilder.CreateIndex("IX_Notifications_TenantId_ResourceId", "Notifications",
            new[] { "TenantId", "ResourceId" });

        migrationBuilder.CreateIndex("IX_AssessmentSchedules_TenantId_Status_NextRunAt", "AssessmentSchedules",
            new[] { "TenantId", "Status", "NextRunAt" });
        migrationBuilder.CreateIndex("IX_AssessmentScheduleRuns_TenantId_IdempotencyKey", "AssessmentScheduleRuns",
            new[] { "TenantId", "IdempotencyKey" }, unique: true);
        migrationBuilder.CreateIndex("IX_AssessmentScheduleRuns_TenantId_ScheduleId_ScheduledFor", "AssessmentScheduleRuns",
            new[] { "TenantId", "ScheduleId", "ScheduledFor" }, unique: true);
        migrationBuilder.CreateIndex("IX_AssessmentScheduleRuns_TenantId_Status_ScheduledFor", "AssessmentScheduleRuns",
            new[] { "TenantId", "Status", "ScheduledFor" });
        migrationBuilder.CreateIndex("IX_AssessmentDriftEvents_TenantId_CreatedAt", "AssessmentDriftEvents",
            new[] { "TenantId", "CreatedAt" });
        migrationBuilder.CreateIndex("IX_AssessmentDriftEvents_TenantId_ScheduleRunId_EventType_StableIdentifier", "AssessmentDriftEvents",
            new[] { "TenantId", "ScheduleRunId", "EventType", "StableIdentifier" }, unique: true);
        migrationBuilder.CreateIndex("IX_Notifications_TenantId_Channel_ResourceId", "Notifications",
            new[] { "TenantId", "Channel", "ResourceId" }, unique: true);

        migrationBuilder.Sql("""
            ALTER TABLE "Notifications"
            ADD CONSTRAINT "FK_Notifications_AssessmentDriftEvents_TenantId_ResourceId"
            FOREIGN KEY ("TenantId", "ResourceId")
            REFERENCES "AssessmentDriftEvents" ("TenantId", "Id")
            ON DELETE CASCADE;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            ALTER TABLE "Notifications"
            DROP CONSTRAINT IF EXISTS "FK_Notifications_AssessmentDriftEvents_TenantId_ResourceId";
            """);
        migrationBuilder.Sql("""
            ALTER TABLE "AssessmentSchedules"
            DROP CONSTRAINT IF EXISTS "FK_AssessmentSchedules_TargetScopes_TenantId_ScopeId";
            """);
        migrationBuilder.DropTable("AssessmentDriftEvents");
        migrationBuilder.DropTable("AssessmentScheduleRuns");
        migrationBuilder.DropTable("AssessmentSchedules");
        migrationBuilder.DropIndex("IX_Notifications_TenantId_ResourceId", "Notifications");
        migrationBuilder.DropIndex("IX_AssessmentDriftEvents_TenantId_ScheduleId", "AssessmentDriftEvents");
        migrationBuilder.DropIndex("IX_Notifications_TenantId_Channel_ResourceId", "Notifications");
        migrationBuilder.DropColumn("ResourceId", "Notifications");
        migrationBuilder.DropColumn("IsRead", "Notifications");
        migrationBuilder.DropColumn("ReadAt", "Notifications");
        migrationBuilder.DropColumn("ReadBy", "Notifications");
        migrationBuilder.DropIndex("IX_TargetScopes_TenantId_Id", "TargetScopes");
    }
}
