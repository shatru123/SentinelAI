using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts;
using SentinelAI.Domain;
using SentinelAI.Security.Policy;

namespace SentinelAI.Application;

public interface IAssessmentScheduleService
{
    Task<AssessmentScheduleResponse> CreateAsync(PrincipalContext principal, CreateAssessmentScheduleRequest request, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<AssessmentScheduleResponse>> ListAsync(PrincipalContext principal, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<AssessmentScheduleRunResponse>?> ListRunsAsync(PrincipalContext principal, Guid scheduleId, CancellationToken cancellationToken);
    Task<AssessmentScheduleResponse?> ChangeStateAsync(PrincipalContext principal, Guid scheduleId, string action, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<AssessmentDriftEventResponse>> ListDriftEventsAsync(PrincipalContext principal, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<AssessmentNotificationResponse>> ListNotificationsAsync(PrincipalContext principal, CancellationToken cancellationToken);
    Task<bool> AcknowledgeAsync(PrincipalContext principal, Guid eventId, CancellationToken cancellationToken);
}

public sealed class AssessmentScheduleService(IAppDbContext db, ITargetScopeValidator validator) : IAssessmentScheduleService
{
    private static readonly HashSet<string> AllowedProfiles = new(StringComparer.OrdinalIgnoreCase)
    {
        WebAssessmentOperationProfiles.Passive,
        WebAssessmentOperationProfiles.SafeActive
    };

    public async Task<AssessmentScheduleResponse> CreateAsync(PrincipalContext principal, CreateAssessmentScheduleRequest request, CancellationToken cancellationToken)
    {
        EnsureOperator(principal);
        if (request.IntervalHours is < 24 or > 2160)
            throw new ScopeValidationException(["Schedule interval must be between 24 hours and 90 days."]);
        var requestedProfile = request.OperationProfile?.Trim();
        if (string.IsNullOrWhiteSpace(requestedProfile) || !AllowedProfiles.Contains(requestedProfile))
            throw new ScopeValidationException(["Only the existing bounded web-assessment profiles can be scheduled."]);

        var now = DateTimeOffset.UtcNow;
        if (request.EndsAt <= now.AddHours(request.IntervalHours))
            throw new ScopeValidationException(["The schedule must allow at least one complete interval before it ends."]);

        var scope = await db.TargetScopes.SingleOrDefaultAsync(x => x.Id == request.ScopeId && x.TenantId == principal.TenantId, cancellationToken)
            ?? throw new KeyNotFoundException("The selected target scope was not found in this tenant.");
        var profile = AllowedProfiles.Single(x => string.Equals(x, requestedProfile, StringComparison.OrdinalIgnoreCase));
        var reason = await ValidateScheduleAuthorizationAsync(db, validator, principal.TenantId, principal.UserId,
            profile, scope, now, request.EndsAt, cancellationToken);
        if (reason is not null) throw new ScopeValidationException([reason]);

        var schedule = new AssessmentSchedule(principal.TenantId, scope.Id, principal.UserId, profile,
            scope.GetAuthorizationFingerprint(), request.IntervalHours, request.EndsAt, now);
        db.AssessmentSchedules.Add(schedule);
        db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "assessment-schedule.created",
            nameof(AssessmentSchedule), schedule.Id, "A bounded reassessment schedule was created against an existing authorized scope."));
        await db.SaveChangesAsync(cancellationToken);
        return ToResponse(schedule);
    }

    public async Task<IReadOnlyCollection<AssessmentScheduleResponse>> ListAsync(PrincipalContext principal, CancellationToken cancellationToken)
    {
        EnsureReader(principal);
        var items = await db.AssessmentSchedules.AsNoTracking()
            .Where(x => x.TenantId == principal.TenantId)
            .OrderByDescending(x => x.CreatedAt)
            .Take(200)
            .ToListAsync(cancellationToken);
        return items.Select(ToResponse).ToArray();
    }

    public async Task<IReadOnlyCollection<AssessmentScheduleRunResponse>?> ListRunsAsync(PrincipalContext principal, Guid scheduleId, CancellationToken cancellationToken)
    {
        EnsureReader(principal);
        var exists = await db.AssessmentSchedules.AsNoTracking()
            .AnyAsync(x => x.Id == scheduleId && x.TenantId == principal.TenantId, cancellationToken);
        if (!exists) return null;
        var items = await db.AssessmentScheduleRuns.AsNoTracking()
            .Where(x => x.TenantId == principal.TenantId && x.ScheduleId == scheduleId)
            .OrderByDescending(x => x.ScheduledFor)
            .Take(100)
            .ToListAsync(cancellationToken);
        return items.Select(ToResponse).ToArray();
    }

    public async Task<AssessmentScheduleResponse?> ChangeStateAsync(PrincipalContext principal, Guid scheduleId, string action, CancellationToken cancellationToken)
    {
        EnsureOperator(principal);
        var normalizedAction = action.Trim().ToLowerInvariant();
        var schedule = await db.AssessmentSchedules.SingleOrDefaultAsync(x => x.Id == scheduleId && x.TenantId == principal.TenantId, cancellationToken);
        if (schedule is null) return null;
        var now = DateTimeOffset.UtcNow;

        switch (normalizedAction)
        {
            case "pause":
                schedule.Pause(now);
                break;
            case "resume":
            {
                var scope = await db.TargetScopes.SingleOrDefaultAsync(x => x.Id == schedule.ScopeId && x.TenantId == principal.TenantId, cancellationToken);
                var reason = scope is null
                    ? "The original target scope no longer exists in this tenant."
                    : !string.Equals(schedule.AuthorizationFingerprint, scope.GetAuthorizationFingerprint(), StringComparison.Ordinal)
                        ? "The original scope authorization changed; review authorization and create a new schedule."
                        : await ValidateScheduleAuthorizationAsync(db, validator, principal.TenantId, schedule.CreatedBy,
                            schedule.OperationProfile, scope, now, schedule.EndsAt, cancellationToken);
                if (reason is not null) schedule.Block(reason, now);
                else schedule.Resume(now);
                break;
            }
            case "disable":
                schedule.Disable(now);
                break;
            default:
                throw new ScopeValidationException(["Supported schedule actions are pause, resume and disable."]);
        }

        db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, $"assessment-schedule.{normalizedAction}",
            nameof(AssessmentSchedule), schedule.Id, $"Schedule {normalizedAction} requested by an authorized operator."));
        await db.SaveChangesAsync(cancellationToken);
        return ToResponse(schedule);
    }

    public async Task<IReadOnlyCollection<AssessmentDriftEventResponse>> ListDriftEventsAsync(PrincipalContext principal, CancellationToken cancellationToken)
    {
        EnsureReader(principal);
        var events = await db.AssessmentDriftEvents.AsNoTracking()
            .Where(x => x.TenantId == principal.TenantId)
            .OrderByDescending(x => x.CreatedAt)
            .Take(200)
            .ToListAsync(cancellationToken);
        return events.Select(ToResponse).ToArray();
    }

    public async Task<IReadOnlyCollection<AssessmentNotificationResponse>> ListNotificationsAsync(PrincipalContext principal, CancellationToken cancellationToken)
    {
        EnsureReader(principal);
        var notifications = await db.Notifications.AsNoTracking()
            .Where(x => x.TenantId == principal.TenantId && x.Channel == "in-app" && x.ResourceId != null)
            .OrderByDescending(x => x.CreatedAt)
            .Take(100)
            .ToListAsync(cancellationToken);
        return notifications.Select(x => new AssessmentNotificationResponse(x.Id, x.ResourceId!.Value, x.Message, x.IsRead, x.CreatedAt)).ToArray();
    }

    public async Task<bool> AcknowledgeAsync(PrincipalContext principal, Guid eventId, CancellationToken cancellationToken)
    {
        EnsureOperator(principal);
        var driftEvent = await db.AssessmentDriftEvents.SingleOrDefaultAsync(x => x.Id == eventId && x.TenantId == principal.TenantId, cancellationToken);
        if (driftEvent is null) return false;
        driftEvent.Acknowledge(principal.UserId, DateTimeOffset.UtcNow);
        var notification = await db.Notifications.SingleOrDefaultAsync(x =>
            x.TenantId == principal.TenantId && x.ResourceId == eventId && x.Channel == "in-app", cancellationToken);
        notification?.MarkRead(principal.UserId);
        db.AuditEvents.Add(new AuditEvent(principal.TenantId, principal.UserId, "assessment-drift.acknowledged",
            nameof(AssessmentDriftEvent), eventId, "Scheduled assessment drift event acknowledged."));
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    internal static async Task<string?> ValidateScheduleAuthorizationAsync(
        IAppDbContext db, ITargetScopeValidator validator, Guid tenantId, Guid creatorId, string profile,
        TargetScope scope, DateTimeOffset now, DateTimeOffset endsAt, CancellationToken cancellationToken)
    {
        if (scope.TenantId != tenantId) return "The original scope is not owned by this tenant.";
        if (scope.ExpiresAt <= now || endsAt >= scope.ExpiresAt || endsAt <= now)
            return "The schedule must end before the existing scope authorization expires.";
        if (!AllowedProfiles.Contains(profile) || !scope.ApprovedOperationProfiles.Contains(profile, StringComparer.OrdinalIgnoreCase))
            return "The operation profile is not currently approved by the original scope.";
        if (scope.Targets.Count != 1 || scope.Targets[0].Kind != TargetKind.Web)
            return "Scheduled reassessment requires one existing web target in the original scope.";

        var scopeValidation = validator.ValidateDefinition(scope, tenantId, now);
        if (!scopeValidation.IsValid) return string.Join(" ", scopeValidation.Errors);

        var creator = await db.Users.AsNoTracking()
            .SingleOrDefaultAsync(x => x.Id == creatorId && x.TenantId == tenantId, cancellationToken);
        if (creator is null || creator.Role is not (UserRole.Admin or UserRole.SecurityAnalyst))
            return "The schedule creator is no longer an active Admin or Security Analyst in this tenant.";

        if (scope.WebHostingMode != WebHostingMode.Private)
        {
            var authorizationIds = scope.PublicTargetVerifications
                .Where(x => x.AuthorizationId.HasValue)
                .Select(x => x.AuthorizationId!.Value)
                .Distinct()
                .ToArray();
            if (authorizationIds.Length == 0)
                return "A current administrator-approved public target authorization is required.";
            var authorizations = await db.PublicTargetAuthorizations.AsNoTracking()
                .Where(x => x.TenantId == tenantId && authorizationIds.Contains(x.Id))
                .ToListAsync(cancellationToken);
            if (authorizations.Count != authorizationIds.Length ||
                authorizations.Any(x => x.GetStatus(now) != PublicTargetAuthorizationStatus.Approved))
                return "A public target authorization is missing, expired or revoked; review and create a new schedule after re-approval.";
        }
        else
        {
            if (string.IsNullOrWhiteSpace(scope.PrivateWorkerIdentity))
                return "The original private worker binding is missing.";
            var worker = await db.Workers.AsNoTracking()
                .SingleOrDefaultAsync(x => x.TenantId == tenantId && x.Identity == scope.PrivateWorkerIdentity, cancellationToken);
            if (worker is null || worker.Status == WorkerStatus.Disabled ||
                !worker.IsHealthyForAdmission(now, TimeSpan.FromSeconds(90)) ||
                !worker.Capabilities.Contains("web-assessment", StringComparer.OrdinalIgnoreCase) ||
                !worker.Capabilities.Contains("private-web-assessment", StringComparer.OrdinalIgnoreCase) ||
                !worker.PrivateAssessmentApproved)
                return "The original private worker is missing, disabled, unhealthy or no longer authorized for private web assessment.";
            if (scope.ApprovedPrivateNetworkRanges.Count == 0 ||
                scope.ApprovedPrivateNetworkRanges.Any(range => !worker.ApprovedPrivateNetworkRanges.Any(approved =>
                    TargetScopeValidator.IsNetworkRangeContainedBy(range, approved))))
                return "The original private network authorization no longer intersects the worker's approved ranges.";
        }

        return null;
    }

    private static void EnsureOperator(PrincipalContext principal)
    {
        if (!principal.CanOperate)
            throw new UnauthorizedAccessException("Only Admins and Security Analysts can manage reassessment schedules.");
    }

    private static void EnsureReader(PrincipalContext principal)
    {
        if (!principal.CanRead)
            throw new UnauthorizedAccessException("The current role cannot read reassessment schedules or drift events.");
    }

    internal static AssessmentScheduleResponse ToResponse(AssessmentSchedule x)
        => new(x.Id, x.ScopeId, x.CreatedBy, x.OperationProfile, x.IntervalHours, x.EndsAt, x.NextRunAt, x.LastRunAt,
            x.LastResult, x.Status, x.BlockedReason, x.CreatedAt);

    internal static AssessmentScheduleRunResponse ToResponse(AssessmentScheduleRun x)
        => new(x.Id, x.ScheduleId, x.ScheduledFor, x.Status, x.JobId, x.AssessmentId, x.BlockedReason, x.CreatedAt);

    internal static AssessmentDriftEventResponse ToResponse(AssessmentDriftEvent x)
        => new(x.Id, x.ScheduleId, x.ScheduleRunId, x.PreviousAssessmentId, x.CurrentAssessmentId, x.EventType,
            x.StableIdentifier, x.PreviousSeverity, x.CurrentSeverity, x.Summary, x.CreatedAt, x.AcknowledgedAt, x.AcknowledgedBy);
}

public sealed record AssessmentDriftChange(string EventType, string StableIdentifier,
    FindingSeverity? PreviousSeverity, FindingSeverity? CurrentSeverity, string Summary);

public static class AssessmentDriftComparer
{
    public static IReadOnlyCollection<AssessmentDriftChange> Compare(
        IReadOnlyCollection<Finding> previousFindings, IReadOnlyCollection<WebAssessmentCheck> previousChecks,
        IReadOnlyCollection<Finding> currentFindings, IReadOnlyCollection<WebAssessmentCheck> currentChecks)
    {
        var changes = new List<AssessmentDriftChange>();
        var previous = previousFindings.GroupBy(Fingerprint)
            .ToDictionary(x => x.Key, x => x.OrderByDescending(f => f.Severity).First());
        var current = currentFindings.GroupBy(Fingerprint)
            .ToDictionary(x => x.Key, x => x.OrderByDescending(f => f.Severity).First());

        foreach (var (key, finding) in current)
        {
            if (!previous.TryGetValue(key, out var oldFinding))
                changes.Add(new AssessmentDriftChange("NewFinding", key, null, finding.Severity,
                    "A finding with a new stable fingerprint was detected by the latest completed assessment."));
            else if (finding.Severity > oldFinding.Severity)
                changes.Add(new AssessmentDriftChange("SeverityIncreased", key, oldFinding.Severity, finding.Severity,
                    "A matching finding increased in severity between completed assessments."));
            else if (finding.Severity < oldFinding.Severity)
                changes.Add(new AssessmentDriftChange("SeverityDecreased", key, oldFinding.Severity, finding.Severity,
                    "A matching finding decreased in severity between completed assessments."));
        }

        foreach (var (key, oldFinding) in previous)
        {
            if (current.ContainsKey(key) || !WasSuccessfullyChecked(oldFinding, currentChecks)) continue;
            changes.Add(new AssessmentDriftChange("NoLongerObserved", key, oldFinding.Severity, null,
                "A previously observed finding was not observed by a corresponding check that completed successfully. This is not a remediation or resolution confirmation."));
        }

        var oldChecks = previousChecks.Where(x => IsSuccessful(x.Status))
            .GroupBy(CheckFingerprint).ToDictionary(x => x.Key, x => x.First());
        var newChecks = currentChecks.GroupBy(CheckFingerprint).ToDictionary(x => x.Key, x => x.First());
        foreach (var (key, oldCheck) in oldChecks)
        {
            if (newChecks.TryGetValue(key, out var newCheck) && IsSuccessful(newCheck.Status)) continue;
            changes.Add(new AssessmentDriftChange("CoverageRegression", key, null, null,
                newCheck is null
                    ? "A check that completed successfully before was not represented in the latest assessment."
                    : "A check that completed successfully before is now skipped, blocked, unsupported or failed."));
        }

        return changes;
    }

    public static string Fingerprint(Finding finding)
    {
        var canonical = string.Join("|",
            Normalize(finding.Category),
            Normalize(finding.HttpMethod),
            Normalize(finding.Parameter),
            NormalizeUrl(finding.AffectedUrl));
        return Hash(canonical);
    }

    private static bool WasSuccessfullyChecked(Finding finding, IReadOnlyCollection<WebAssessmentCheck> checks)
    {
        var category = Normalize(finding.Category);
        if (category.Length == 0) return false;
        return checks.Any(check =>
            (Normalize(check.CheckId) == category || Normalize(check.Category) == category) &&
            check.Status == WebCheckStatus.Passed &&
            SameEndpoint(finding.AffectedUrl, check.AffectedEndpoint));
    }

    private static bool SameEndpoint(string? findingUrl, string? checkUrl)
    {
        if (string.IsNullOrWhiteSpace(findingUrl) || string.IsNullOrWhiteSpace(checkUrl))
            return string.IsNullOrWhiteSpace(findingUrl) && string.IsNullOrWhiteSpace(checkUrl);
        return string.Equals(NormalizeUrl(findingUrl), NormalizeUrl(checkUrl), StringComparison.Ordinal);
    }

    private static string CheckFingerprint(WebAssessmentCheck check)
        => Hash($"{Normalize(check.CheckId)}|{Normalize(check.Category)}|{NormalizeUrl(check.AffectedEndpoint)}");

    private static bool IsSuccessful(WebCheckStatus status)
        => status is WebCheckStatus.Passed or WebCheckStatus.FindingDetected or WebCheckStatus.PotentialFinding or
            WebCheckStatus.Confirmed or WebCheckStatus.Potential or WebCheckStatus.Informational;

    private static string NormalizeUrl(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        if (Uri.TryCreate(value, UriKind.Absolute, out var uri))
            return $"{uri.Scheme.ToLowerInvariant()}://{uri.IdnHost.ToLowerInvariant()}:{uri.Port}{uri.AbsolutePath.TrimEnd('/')}";
        return value.Trim().Split('?', '#')[0].TrimEnd('/');
    }

    private static string Normalize(string? value) => (value ?? string.Empty).Trim().ToLowerInvariant();
    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}

public sealed class AssessmentScheduleProcessor(
    IAppDbContextFactory dbFactory,
    ITargetScopeValidator validator,
    IScanJobQueue queue,
    ILogger<AssessmentScheduleProcessor> logger)
{
    public async Task RunOnceAsync(int batchSize = 20, CancellationToken cancellationToken = default)
    {
        var boundedBatch = Math.Clamp(batchSize, 1, 100);
        var dueIds = await LoadDueScheduleIdsAsync(boundedBatch, cancellationToken);
        foreach (var id in dueIds)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try { await DispatchOneAsync(id, cancellationToken); }
            catch (DbUpdateConcurrencyException)
            {
                logger.LogDebug("A different scheduler instance claimed a due occurrence for schedule {ScheduleId}.", id);
            }
            catch (DbUpdateException exception)
            {
                logger.LogDebug(exception, "The due occurrence for schedule {ScheduleId} was claimed by another instance or failed to persist; it will be retried.", id);
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                logger.LogWarning(exception, "Could not dispatch due schedule {ScheduleId}; the occurrence remains eligible for retry.", id);
            }
        }

        var pendingRunIds = await LoadPendingRunIdsAsync(boundedBatch, cancellationToken);
        foreach (var runId in pendingRunIds)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try { await ReconcileRunAsync(runId, cancellationToken); }
            catch (DbUpdateConcurrencyException)
            {
                logger.LogDebug("Scheduled run {RunId} was reconciled by another scheduler instance.", runId);
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                logger.LogWarning(exception, "Could not reconcile scheduled run {RunId}; it will be retried.", runId);
            }
        }
    }

    private async Task<Guid[]> LoadDueScheduleIdsAsync(int batchSize, CancellationToken cancellationToken)
    {
        await using var db = dbFactory.CreateDbContext();
        var now = DateTimeOffset.UtcNow;
        return await db.AssessmentSchedules.AsNoTracking()
            .Where(x => x.Status == AssessmentScheduleStatus.Active && x.NextRunAt != null && x.NextRunAt <= now &&
                !db.AssessmentScheduleRuns.Any(run => run.TenantId == x.TenantId && run.ScheduleId == x.Id &&
                    run.Status == AssessmentScheduleRunStatus.Queued))
            .OrderBy(x => x.NextRunAt)
            .Take(batchSize)
            .Select(x => x.Id)
            .ToArrayAsync(cancellationToken);
    }

    private async Task DispatchOneAsync(Guid scheduleId, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        Guid? queuedJobId = null;
        Guid tenantId = Guid.Empty;
        await using var db = dbFactory.CreateDbContext();
        await using var transaction = await db.BeginTransactionAsync(cancellationToken);
        var schedule = await db.AssessmentSchedules.SingleOrDefaultAsync(x => x.Id == scheduleId, cancellationToken);
        if (schedule is null || schedule.Status != AssessmentScheduleStatus.Active || schedule.NextRunAt is null || schedule.NextRunAt > now)
            return;

        tenantId = schedule.TenantId;
        var hasOutstandingRun = await db.AssessmentScheduleRuns.AsNoTracking().AnyAsync(x =>
            x.TenantId == schedule.TenantId && x.ScheduleId == schedule.Id &&
            x.Status == AssessmentScheduleRunStatus.Queued, cancellationToken);
        if (hasOutstandingRun) return;

        var scheduledFor = schedule.NextRunAt.Value;
        var run = new AssessmentScheduleRun(schedule.TenantId, schedule.Id, scheduledFor, now);
        var scope = await db.TargetScopes.SingleOrDefaultAsync(x => x.Id == schedule.ScopeId && x.TenantId == schedule.TenantId, cancellationToken);
        var reason = scope is null
            ? "The original target scope no longer exists in this tenant."
            : !string.Equals(schedule.AuthorizationFingerprint, scope.GetAuthorizationFingerprint(), StringComparison.Ordinal)
                ? "The original scope authorization changed; review authorization and create a new schedule."
                : await AssessmentScheduleService.ValidateScheduleAuthorizationAsync(db, validator, schedule.TenantId,
                    schedule.CreatedBy, schedule.OperationProfile, scope, now, schedule.EndsAt, cancellationToken);

        db.AssessmentScheduleRuns.Add(run);
        if (reason is not null)
        {
            run.Block(reason, now);
            schedule.Block(reason, now);
            db.AuditEvents.Add(new AuditEvent(schedule.TenantId, null, "assessment-schedule.run-blocked",
                nameof(AssessmentScheduleRun), run.Id, "A scheduled occurrence was blocked because current authorization revalidation failed."));
        }
        else
        {
            if (!schedule.TryAdvance(scheduledFor, now))
                throw new DbUpdateConcurrencyException("The schedule occurrence changed while it was being claimed.");

            var webTarget = scope!.Targets[0].Value;
            var job = new AgentJob(schedule.TenantId, scope.Id, schedule.CreatedBy, schedule.OperationProfile);
            var assessment = new WebAssessment(schedule.TenantId, job.Id, scope.Id, webTarget,
                schedule.OperationProfile, scope.WebHostingMode ?? WebHostingMode.Public);
            db.AgentJobs.Add(job);
            db.AgentExecutions.Add(new AgentExecution(job.Id, "AuthorizedWebAssessmentAgent"));
            db.WebAssessments.Add(assessment);
            db.OutboxMessages.Add(new OutboxMessage(schedule.TenantId, OutboxMessageTypes.ScanJob,
                OutboxMessagePayload.Serialize(new OutboxJobEnvelope(job.Id, schedule.TenantId,
                    scope.WebHostingMode == WebHostingMode.Private ? scope.PrivateWorkerIdentity : null))));
            db.AuditEvents.Add(new AuditEvent(schedule.TenantId, schedule.CreatedBy, "assessment-schedule.run-queued",
                nameof(AssessmentScheduleRun), run.Id, "A due scheduled assessment was queued through the standard worker outbox."));
            run.MarkQueued(job.Id, assessment.Id);
            queuedJobId = job.Id;
        }

        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        // In-memory development queues are not backed by the outbox dispatcher.
        // RabbitMQ deployments consume the transactionally written outbox record.
        if (queuedJobId.HasValue && queue is IImmediateScanJobQueue)
            await queue.EnqueueAsync(queuedJobId.Value, tenantId, cancellationToken);
    }

    private async Task<Guid[]> LoadPendingRunIdsAsync(int batchSize, CancellationToken cancellationToken)
    {
        await using var db = dbFactory.CreateDbContext();
        return await db.AssessmentScheduleRuns.AsNoTracking()
            .Where(x => x.Status == AssessmentScheduleRunStatus.Queued && x.AssessmentId != null)
            .OrderBy(x => x.ScheduledFor)
            .Take(batchSize)
            .Select(x => x.Id)
            .ToArrayAsync(cancellationToken);
    }

    private async Task ReconcileRunAsync(Guid runId, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        await using var db = dbFactory.CreateDbContext();
        await using var transaction = await db.BeginTransactionAsync(cancellationToken);
        var run = await db.AssessmentScheduleRuns.SingleOrDefaultAsync(x => x.Id == runId, cancellationToken);
        if (run is null || run.Status != AssessmentScheduleRunStatus.Queued || run.AssessmentId is null) return;

        var assessment = await db.WebAssessments.SingleOrDefaultAsync(x =>
            x.Id == run.AssessmentId && x.TenantId == run.TenantId, cancellationToken);
        if (assessment is null)
        {
            run.Fail("The queued assessment record is missing.", now);
        }
        else if (assessment.Status == WebAssessmentStatus.Completed)
        {
            var previous = assessment.CompletedAt is null ? null : await db.WebAssessments.AsNoTracking()
                .Where(x => x.TenantId == run.TenantId && x.ScopeId == assessment.ScopeId &&
                    x.Profile == assessment.Profile && x.Status == WebAssessmentStatus.Completed &&
                    x.Id != assessment.Id &&
                    (x.CompletedAt < assessment.CompletedAt ||
                     (x.CompletedAt == assessment.CompletedAt && x.CreatedAt < assessment.CreatedAt)))
                .OrderByDescending(x => x.CompletedAt)
                .ThenByDescending(x => x.CreatedAt)
                .FirstOrDefaultAsync(cancellationToken);

            if (previous is not null)
            {
                var oldFindings = await db.Findings.AsNoTracking()
                    .Where(x => x.TenantId == run.TenantId && x.AssessmentId == previous.Id).ToListAsync(cancellationToken);
                var newFindings = await db.Findings.AsNoTracking()
                    .Where(x => x.TenantId == run.TenantId && x.AssessmentId == assessment.Id).ToListAsync(cancellationToken);
                var oldChecks = await db.WebAssessmentChecks.AsNoTracking()
                    .Where(x => x.TenantId == run.TenantId && x.AssessmentId == previous.Id).ToListAsync(cancellationToken);
                var newChecks = await db.WebAssessmentChecks.AsNoTracking()
                    .Where(x => x.TenantId == run.TenantId && x.AssessmentId == assessment.Id).ToListAsync(cancellationToken);

                foreach (var change in AssessmentDriftComparer.Compare(oldFindings, oldChecks, newFindings, newChecks))
                {
                    var driftEvent = new AssessmentDriftEvent(run.TenantId, run.ScheduleId, run.Id, previous.Id, assessment.Id,
                        change.EventType, change.StableIdentifier, change.PreviousSeverity, change.CurrentSeverity, change.Summary, now);
                    db.AssessmentDriftEvents.Add(driftEvent);
                    db.Notifications.Add(new Notification(run.TenantId, "in-app",
                        $"Scheduled assessment drift: {change.EventType}. Review the event in the SentinelAI Schedules workspace.",
                        driftEvent.Id));
                }
            }

            run.Complete(now);
        }
        else if (assessment.Status is WebAssessmentStatus.Failed or WebAssessmentStatus.Cancelled or WebAssessmentStatus.Expired)
        {
            run.Fail("The scheduled assessment did not complete successfully.", now);
        }
        else
        {
            return;
        }

        var schedule = await db.AssessmentSchedules.SingleOrDefaultAsync(x =>
            x.Id == run.ScheduleId && x.TenantId == run.TenantId, cancellationToken);
        schedule?.RecordResult(run.Status.ToString(), now);
        if (schedule is { Status: AssessmentScheduleStatus.Active, NextRunAt: null })
        {
            var otherPendingRuns = await db.AssessmentScheduleRuns.AsNoTracking().AnyAsync(x =>
                x.TenantId == run.TenantId && x.ScheduleId == run.ScheduleId &&
                x.Id != run.Id && x.Status == AssessmentScheduleRunStatus.Queued, cancellationToken);
            if (!otherPendingRuns) schedule.Complete(now);
        }
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }
}
