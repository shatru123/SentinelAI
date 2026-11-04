namespace SentinelAI.Contracts;

using SentinelAI.Domain;

public sealed record CreateAssessmentScheduleRequest(Guid ScopeId, string OperationProfile, int IntervalHours, DateTimeOffset EndsAt);
public sealed record AssessmentScheduleResponse(Guid Id, Guid ScopeId, Guid CreatedBy, string OperationProfile, int IntervalHours,
    DateTimeOffset EndsAt, DateTimeOffset? NextRunAt, DateTimeOffset? LastRunAt, string? LastResult,
    AssessmentScheduleStatus Status, string? BlockedReason, DateTimeOffset CreatedAt);
public sealed record AssessmentScheduleRunResponse(Guid Id, Guid ScheduleId, DateTimeOffset ScheduledFor,
    AssessmentScheduleRunStatus Status, Guid? JobId, Guid? AssessmentId, string? BlockedReason, DateTimeOffset CreatedAt);
public sealed record AssessmentDriftEventResponse(Guid Id, Guid ScheduleId, Guid ScheduleRunId, Guid PreviousAssessmentId,
    Guid CurrentAssessmentId, string EventType, string StableIdentifier, FindingSeverity? PreviousSeverity,
    FindingSeverity? CurrentSeverity, string Summary, DateTimeOffset CreatedAt, DateTimeOffset? AcknowledgedAt, Guid? AcknowledgedBy);
public sealed record AssessmentNotificationResponse(Guid Id, Guid EventId, string Message, bool IsRead, DateTimeOffset CreatedAt);
