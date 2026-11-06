using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SentinelAI.Infrastructure;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations;

[DbContext(typeof(AppDbContext))]
[Migration("20261105100000_Phase5WorkerCertificates")]
public sealed class Phase5WorkerCertificates : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "WorkerClientCertificates",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                WorkerIdentity = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                ThumbprintSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                SerialNumber = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                Subject = table.Column<string>(type: "text", nullable: false),
                Issuer = table.Column<string>(type: "text", nullable: false),
                NotBefore = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                NotAfter = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                EnrolledBy = table.Column<Guid>(type: "uuid", nullable: false),
                EnrolledAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                RevokedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                RevokedBy = table.Column<Guid>(type: "uuid", nullable: true),
                RevocationReason = table.Column<string>(type: "text", nullable: true)
            },
            constraints: table => table.PrimaryKey("PK_WorkerClientCertificates", x => x.Id));

        migrationBuilder.CreateIndex(
            name: "IX_WorkerClientCertificates_ThumbprintSha256",
            table: "WorkerClientCertificates",
            column: "ThumbprintSha256",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_WorkerClientCertificates_TenantId_WorkerIdentity_RevokedAt_NotAfter",
            table: "WorkerClientCertificates",
            columns: new[] { "TenantId", "WorkerIdentity", "RevokedAt", "NotAfter" });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "WorkerClientCertificates");
    }
}
