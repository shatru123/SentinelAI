using SentinelAI.Domain;

namespace SentinelAI.UnitTests;

public sealed class AssessmentScheduleDomainTests
{
    [Fact]
    public void Occurrence_advances_from_the_scheduled_time_and_stops_before_expiry()
    {
        var created = new DateTimeOffset(2026, 11, 4, 10, 0, 0, TimeSpan.Zero);
        var schedule = new AssessmentSchedule(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            "web-assessment-passive", new string('A', 64), 24, created.AddHours(48), created);

        var due = schedule.NextRunAt!.Value;
        Assert.True(schedule.TryAdvance(due, due.AddSeconds(10)));

        Assert.Equal(due, schedule.LastRunAt);
        Assert.Null(schedule.NextRunAt);
        Assert.Equal(AssessmentScheduleStatus.Active, schedule.Status);

        // The final run is still in flight; completion is recorded only after reconciliation.
        schedule.Complete(due.AddMinutes(5));
        Assert.Equal(AssessmentScheduleStatus.Completed, schedule.Status);
    }

    [Fact]
    public void Missed_intervals_are_coalesced_to_the_next_future_occurrence()
    {
        var created = new DateTimeOffset(2026, 11, 4, 10, 0, 0, TimeSpan.Zero);
        var schedule = new AssessmentSchedule(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            "web-assessment-passive", new string('D', 64), 24, created.AddDays(10), created);

        var firstDue = schedule.NextRunAt!.Value;
        Assert.True(schedule.TryAdvance(firstDue, created.AddDays(4).AddHours(1)));

        Assert.Equal(firstDue, schedule.LastRunAt);
        Assert.Equal(created.AddDays(5), schedule.NextRunAt);
        Assert.Equal(AssessmentScheduleStatus.Active, schedule.Status);
    }

    [Fact]
    public void Pause_and_resume_recalculate_the_next_run_without_changing_scope()
    {
        var created = DateTimeOffset.UtcNow;
        var scopeId = Guid.NewGuid();
        var schedule = new AssessmentSchedule(Guid.NewGuid(), scopeId, Guid.NewGuid(),
            "web-assessment-passive", new string('B', 64), 24, created.AddDays(10), created);

        schedule.Pause(created.AddHours(1));
        Assert.Equal(AssessmentScheduleStatus.Paused, schedule.Status);
        Assert.Null(schedule.NextRunAt);

        schedule.Resume(created.AddHours(3));
        Assert.Equal(AssessmentScheduleStatus.Active, schedule.Status);
        Assert.Equal(created.AddHours(27), schedule.NextRunAt);
        Assert.Equal(scopeId, schedule.ScopeId);
    }

    [Fact]
    public void Blocked_schedule_cannot_be_resumed_and_can_only_be_replaced_after_review()
    {
        var now = DateTimeOffset.UtcNow;
        var schedule = new AssessmentSchedule(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            "web-assessment-passive", new string('C', 64), 24, now.AddDays(5), now);

        schedule.Block("The scope authorization was revoked.", now.AddHours(1));

        Assert.Equal(AssessmentScheduleStatus.Blocked, schedule.Status);
        Assert.Null(schedule.NextRunAt);
        Assert.Contains("revoked", schedule.BlockedReason, StringComparison.OrdinalIgnoreCase);
        Assert.Throws<InvalidOperationException>(() => schedule.Resume(now.AddHours(2)));
    }

    [Fact]
    public void Schedule_occurrence_idempotency_is_stable_across_time_zone_offsets()
    {
        var tenantId = Guid.NewGuid();
        var scheduleId = Guid.NewGuid();
        var local = new DateTimeOffset(2026, 11, 4, 10, 0, 0, TimeSpan.FromHours(5.5));
        var utc = local.ToUniversalTime();

        var first = new AssessmentScheduleRun(tenantId, scheduleId, local, local);
        var retry = new AssessmentScheduleRun(tenantId, scheduleId, utc, utc);

        Assert.Equal(first.IdempotencyKey, retry.IdempotencyKey);
        Assert.NotEqual(first.Id, retry.Id);
    }
}
