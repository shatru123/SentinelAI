using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SentinelAI.Infrastructure;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations;

[DbContext(typeof(AppDbContext))]
[Migration("20261104120000_Phase42FindingAIAnalysis")]
public partial class Phase42FindingAIAnalysis : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddUniqueConstraint(name: "AK_Findings_TenantId_Id", table: "Findings", columns: new[] { "TenantId", "Id" });
        migrationBuilder.CreateTable(
            name: "FindingAIAnalyses",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                FindingId = table.Column<Guid>(type: "uuid", nullable: false),
                ActorId = table.Column<Guid>(type: "uuid", nullable: false),
                Provider = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                Model = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                PromptTemplateVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                EvidenceSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                Summary = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: false),
                ResultJson = table.Column<string>(type: "text", nullable: false),
                InputTokens = table.Column<int>(type: "integer", nullable: true),
                OutputTokens = table.Column<int>(type: "integer", nullable: true),
                ResponseId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                FinishReason = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_FindingAIAnalyses", x => x.Id);
                table.ForeignKey(name: "FK_FindingAIAnalyses_Findings_TenantId_FindingId",
                    columns: x => new { x.TenantId, x.FindingId }, principalTable: "Findings",
                    principalColumns: new[] { "TenantId", "Id" }, onDelete: ReferentialAction.Cascade);
            });
        migrationBuilder.CreateIndex(name: "IX_FindingAIAnalyses_TenantId_FindingId_CreatedAt",
            table: "FindingAIAnalyses", columns: new[] { "TenantId", "FindingId", "CreatedAt" });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "FindingAIAnalyses");
        migrationBuilder.DropUniqueConstraint(name: "AK_Findings_TenantId_Id", table: "Findings");
    }
}
