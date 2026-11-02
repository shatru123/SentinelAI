using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Infrastructure;
using SentinelAI.Infrastructure;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations;

/// <summary>
/// Makes jobs created by pre-lease versions recoverable. A Running row without
/// a lease expiry cannot be safely owned by any worker, so it is returned to the
/// queue atomically with its execution reset to Pending.
/// </summary>
[DbContext(typeof(AppDbContext))]
[Migration("20261102123000_Phase122LegacyLeaseRecovery")]
public partial class Phase122LegacyLeaseRecovery : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(@"
UPDATE ""AgentJobs""
SET ""Status"" = 0,
    ""StartedAt"" = NULL,
    ""AssignedWorkerIdentity"" = NULL,
    ""LeaseOwnerWorkerId"" = NULL,
    ""LeaseAcquiredAt"" = NULL,
    ""LeaseExpiresAt"" = NULL,
    ""LastLeaseHeartbeatAt"" = NULL,
    ""FailureReason"" = 'Recovered during lease migration.'
WHERE ""Status"" = 1 AND ""LeaseExpiresAt"" IS NULL;");

        migrationBuilder.Sql(@"
UPDATE ""AgentExecutions"" AS execution
SET ""Status"" = 0,
    ""StartedAt"" = NULL,
    ""CompletedAt"" = NULL,
    ""Error"" = 'Recovered during lease migration.'
WHERE ""Status"" = 1
  AND EXISTS (
      SELECT 1 FROM ""AgentJobs"" AS job
      WHERE job.""Id"" = execution.""AgentJobId""
        AND job.""Status"" = 0
        AND job.""FailureReason"" = 'Recovered during lease migration.'
  );");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        // Recovery is intentionally not reversed: restoring an unowned Running
        // state would reintroduce the reliability and data-integrity defect.
    }
}
