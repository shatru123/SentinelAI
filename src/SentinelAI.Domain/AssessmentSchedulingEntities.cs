using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace SentinelAI.Domain;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AssessmentScheduleStatus { Active, Paused, Blocked, Disabled, Completed }

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AssessmentScheduleRunStatus { Queued, Completed, Failed, Blocked }

public sealed class AssessmentSchedule
{
    private AssessmentSchedule() { }

    public AssessmentSchedule(Guid tenantId, Guid scopeId, Guid createdBy, string operationProfile,
        string authorizationFingerprint, int intervalHours, DateTimeOffset endsAt, DateTimeOffset now)
    {
        Id = Guid.NewGuid();
        TenantId = tenantId;
        ScopeId = scopeId;
        CreatedBy = createdBy;
        OperationProfile = operationProfile;
        AuthorizationFingerprint = authorizationFingerprint;
        IntervalHours = intervalHours;
        EndsAt = endsAt;
        CreatedAt = now;
        UpdatedAt = now;
        NextRunAt = now.AddHours(intervalHours);
        Status = AssessmentScheduleStatus.Active;
        RowVersion = Guid.NewGuid().ToByteArray();
    }

    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid ScopeId { get; private set; }
    public Guid CreatedBy { get; private set; }
    public string OperationProfile { get; private set; } = string.Empty;
    public string AuthorizationFingerprint { get; private set; } = string.Empty;
    public int IntervalHours { get; private set; }
    public DateTimeOffset EndsAt { get; private set; }
    public DateTimeOffset? NextRunAt { get; private set; }
    public DateTimeOffset? LastRunAt { get; private set; }
    public string? LastResult { get; private set; }
    public AssessmentScheduleStatus Status { get; private set; }
    public string? BlockedReason { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset UpdatedAt { get; private set; }
    public byte[] RowVersion { get; private set; } = Guid.NewGuid().ToByteArray();

    public bool TryAdvance(DateTimeOffset scheduledFor, DateTimeOffset now)
    {
        if (Status != AssessmentScheduleStatus.Active || NextRunAt != scheduledFor) return false;
        LastRunAt = scheduledFor;
        LastResult = "Queued";
        var next = scheduledFor.AddHours(IntervalHours);
        // Coalesce missed occurrences after downtime instead of dispatching a catch-up burst.
        while (next <= now && next < EndsAt)
            next = next.AddHours(IntervalHours);

        if (next >= EndsAt)
            NextRunAt = null;
        else
            NextRunAt = next;
        UpdatedAt = now;
        Touch();
        return true;
    }

    public void Pause(DateTimeOffset now)
    {
        if (Status != AssessmentScheduleStatus.Active || NextRunAt is null)
            throw new InvalidOperationException("Only an active schedule with a future occurrence can be paused.");
        Status = AssessmentScheduleStatus.Paused;
        NextRunAt = null;
        UpdatedAt = now;
        Touch();
    }

    public void Resume(DateTimeOffset now)
    {
        if (Status != AssessmentScheduleStatus.Paused)
            throw new InvalidOperationException("Only a paused schedule can be resumed.");
        if (now >= EndsAt)
            throw new InvalidOperationException("The schedule end time has passed; create a new schedule.");
        var nextRun = now.AddHours(IntervalHours);
        if (nextRun >= EndsAt)
            throw new InvalidOperationException("The schedule does not have enough remaining authorization time for another run.");
        NextRunAt = nextRun;
        Status = AssessmentScheduleStatus.Active;
        BlockedReason = null;
        LastResult = "Resumed";
        UpdatedAt = now;
        Touch();
    }

    public void Disable(DateTimeOffset now)
    {
        if (Status == AssessmentScheduleStatus.Completed)
            throw new InvalidOperationException("A completed schedule cannot be changed.");
        Status = AssessmentScheduleStatus.Disabled;
        NextRunAt = null;
        UpdatedAt = now;
        Touch();
    }

    public void Block(string reason, DateTimeOffset now)
    {
        Status = AssessmentScheduleStatus.Blocked;
        NextRunAt = null;
        BlockedReason = Limit(reason, 500);
        LastResult = "Blocked";
        UpdatedAt = now;
        Touch();
    }

    public void RecordResult(string result, DateTimeOffset now)
    {
        LastResult = Limit(result, 100);
        UpdatedAt = now;
        Touch();
    }

    public void Complete(DateTimeOffset now)
    {
        if (Status != AssessmentScheduleStatus.Active || NextRunAt is not null)
            throw new InvalidOperationException("A schedule can complete only after its final occurrence has been queued and no future occurrence remains.");
        Status = AssessmentScheduleStatus.Completed;
        UpdatedAt = now;
        Touch();
    }

    private void Touch() => RowVersion = Guid.NewGuid().ToByteArray();

    private static string Limit(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value)) return "The run was blocked by current authorization policy.";
        var trimmed = value.Trim();
        return trimmed[..Math.Min(trimmed.Length, max)];
    }
}

public sealed class AssessmentScheduleRun
{
    private AssessmentScheduleRun() { }

    public AssessmentScheduleRun(Guid tenantId, Guid scheduleId, DateTimeOffset scheduledFor, DateTimeOffset now)
    {
        Id = Guid.NewGuid();
        TenantId = tenantId;
        ScheduleId = scheduleId;
        ScheduledFor = scheduledFor;
        IdempotencyKey = CreateIdempotencyKey(tenantId, scheduleId, scheduledFor);
        Status = AssessmentScheduleRunStatus.Queued;
        CreatedAt = now;
    }

    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid ScheduleId { get; private set; }
    public DateTimeOffset ScheduledFor { get; private set; }
    public string IdempotencyKey { get; private set; } = string.Empty;
    public AssessmentScheduleRunStatus Status { get; private set; }
    public Guid? JobId { get; private set; }
    public Guid? AssessmentId { get; private set; }
    public string? BlockedReason { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? CompletedAt { get; private set; }
    public DateTimeOffset? ComparedAt { get; private set; }

    public void MarkQueued(Guid jobId, Guid assessmentId)
    {
        JobId = jobId;
        AssessmentId = assessmentId;
        Status = AssessmentScheduleRunStatus.Queued;
    }

    public void Block(string reason, DateTimeOffset now)
    {
        Status = AssessmentScheduleRunStatus.Blocked;
        BlockedReason = Limit(reason, 500);
        CompletedAt = now;
    }

    public void Complete(DateTimeOffset now)
    {
        Status = AssessmentScheduleRunStatus.Completed;
        CompletedAt = now;
        ComparedAt = now;
    }

    public void Fail(string reason, DateTimeOffset now)
    {
        Status = AssessmentScheduleRunStatus.Failed;
        BlockedReason = Limit(reason, 500);
        CompletedAt = now;
        ComparedAt = now;
    }

    private static string CreateIdempotencyKey(Guid tenantId, Guid scheduleId, DateTimeOffset scheduledFor)
    {
        var canonical = $"{tenantId:N}|{scheduleId:N}|{scheduledFor.UtcDateTime.Ticks}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static string Limit(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value)) return "The occurrence could not be completed.";
        var trimmed = value.Trim();
        return trimmed[..Math.Min(trimmed.Length, max)];
    }
}

public sealed class AssessmentDriftEvent
{
    private AssessmentDriftEvent() { }

    public AssessmentDriftEvent(Guid tenantId, Guid scheduleId, Guid scheduleRunId,
        Guid previousAssessmentId, Guid currentAssessmentId, string eventType, string stableIdentifier,
        FindingSeverity? previousSeverity, FindingSeverity? currentSeverity, string summary, DateTimeOffset now)
    {
        Id = Guid.NewGuid();
        TenantId = tenantId;
        ScheduleId = scheduleId;
        ScheduleRunId = scheduleRunId;
        PreviousAssessmentId = previousAssessmentId;
        CurrentAssessmentId = currentAssessmentId;
        EventType = eventType;
        StableIdentifier = stableIdentifier;
        PreviousSeverity = previousSeverity;
        CurrentSeverity = currentSeverity;
        var safeSummary = string.IsNullOrWhiteSpace(summary) ? "Scheduled assessment drift was detected." : summary.Trim();
        Summary = safeSummary[..Math.Min(safeSummary.Length, 500)];
        CreatedAt = now;
    }

    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid ScheduleId { get; private set; }
    public Guid ScheduleRunId { get; private set; }
    public Guid PreviousAssessmentId { get; private set; }
    public Guid CurrentAssessmentId { get; private set; }
    public string EventType { get; private set; } = string.Empty;
    public string StableIdentifier { get; private set; } = string.Empty;
    public FindingSeverity? PreviousSeverity { get; private set; }
    public FindingSeverity? CurrentSeverity { get; private set; }
    public string Summary { get; private set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? AcknowledgedAt { get; private set; }
    public Guid? AcknowledgedBy { get; private set; }

    public void Acknowledge(Guid actorId, DateTimeOffset now)
    {
        AcknowledgedAt ??= now;
        AcknowledgedBy ??= actorId;
    }
}
