using SentinelAI.Application;
using SentinelAI.Domain;

namespace SentinelAI.UnitTests;

public sealed class AssessmentDriftComparerTests
{
    private readonly Guid tenantId = Guid.NewGuid();
    private readonly Guid previousAssessmentId = Guid.NewGuid();
    private readonly Guid currentAssessmentId = Guid.NewGuid();

    [Fact]
    public void Query_string_changes_do_not_change_finding_fingerprint_and_severity_changes_are_reported()
    {
        var previous = Finding("security-headers", FindingSeverity.Medium, "https://example.test/app?nonce=one");
        var current = Finding("security-headers", FindingSeverity.High, "https://example.test/app?nonce=two");

        var changes = AssessmentDriftComparer.Compare([previous], [], [current], []);

        var change = Assert.Single(changes);
        Assert.Equal("SeverityIncreased", change.EventType);
        Assert.Equal(FindingSeverity.Medium, change.PreviousSeverity);
        Assert.Equal(FindingSeverity.High, change.CurrentSeverity);
        Assert.Equal(AssessmentDriftComparer.Fingerprint(previous), change.StableIdentifier);
    }

    [Fact]
    public void Severity_decrease_is_reported_without_treating_the_finding_as_resolved()
    {
        var previous = Finding("security-headers", FindingSeverity.Critical, "https://example.test/app");
        var current = Finding("security-headers", FindingSeverity.Medium, "https://example.test/app");

        var change = Assert.Single(AssessmentDriftComparer.Compare([previous], [], [current], []));

        Assert.Equal("SeverityDecreased", change.EventType);
        Assert.Equal(FindingSeverity.Critical, change.PreviousSeverity);
        Assert.Equal(FindingSeverity.Medium, change.CurrentSeverity);
        Assert.Equal(AssessmentDriftComparer.Fingerprint(previous), change.StableIdentifier);
    }

    [Fact]
    public void New_finding_is_reported_with_a_stable_fingerprint()
    {
        var current = Finding("transport-security", FindingSeverity.Critical, "https://example.test/");

        var changes = AssessmentDriftComparer.Compare([], [], [current], []);

        var change = Assert.Single(changes);
        Assert.Equal("NewFinding", change.EventType);
        Assert.Equal(64, change.StableIdentifier.Length);
    }

    [Fact]
    public void Missing_finding_is_not_reported_as_no_longer_observed_without_a_successful_check()
    {
        var previous = Finding("security-headers", FindingSeverity.High, "https://example.test/app");
        var noChecks = AssessmentDriftComparer.Compare([previous], [], [], []);
        var failedCheck = Check(WebCheckStatus.FailedToExecute);

        var failed = AssessmentDriftComparer.Compare([previous], [Check(WebCheckStatus.Passed)], [], [failedCheck]);

        Assert.DoesNotContain(noChecks, x => x.EventType == "NoLongerObserved");
        Assert.DoesNotContain(failed, x => x.EventType == "NoLongerObserved");
    }

    [Fact]
    public void Missing_finding_is_only_no_longer_observed_after_corresponding_check_passes()
    {
        var previous = Finding("security-headers", FindingSeverity.High, "https://example.test/app");
        var changes = AssessmentDriftComparer.Compare(
            [previous], [Check(WebCheckStatus.FindingDetected)], [], [Check(WebCheckStatus.Passed)]);

        var change = Assert.Single(changes);
        Assert.Equal("NoLongerObserved", change.EventType);
        Assert.Contains("not a remediation or resolution confirmation", change.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Missing_finding_endpoint_does_not_match_a_check_at_an_unknown_or_different_endpoint()
    {
        var previous = Finding("security-headers", FindingSeverity.High, null);

        var changes = AssessmentDriftComparer.Compare(
            [previous], [Check(WebCheckStatus.FindingDetected)], [], [Check(WebCheckStatus.Passed)]);

        Assert.DoesNotContain(changes, x => x.EventType == "NoLongerObserved");
    }

    [Fact]
    public void Missing_successful_check_is_reported_as_coverage_regression()
    {
        var prior = Check(WebCheckStatus.Passed);
        var absent = AssessmentDriftComparer.Compare([], [prior], [], []);

        Assert.Contains(absent, x => x.EventType == "CoverageRegression");
    }

    [Theory]
    [InlineData(WebCheckStatus.Skipped)]
    [InlineData(WebCheckStatus.BlockedByAuthorization)]
    [InlineData(WebCheckStatus.Unsupported)]
    [InlineData(WebCheckStatus.FailedToExecute)]
    public void Non_successful_recheck_is_reported_as_coverage_regression(WebCheckStatus currentStatus)
    {
        var prior = Check(WebCheckStatus.Passed);
        var current = Check(currentStatus);

        var change = Assert.Single(AssessmentDriftComparer.Compare([], [prior], [], [current]));

        Assert.Equal("CoverageRegression", change.EventType);
        Assert.Contains("skipped, blocked, unsupported or failed", change.Summary, StringComparison.OrdinalIgnoreCase);
    }

    private Finding Finding(string category, FindingSeverity severity, string? url)
    {
        var finding = new Finding(tenantId, null, "Test finding", severity);
        finding.ConfigureAssessmentDetails(previousAssessmentId, category, "high", url, "GET", "q",
            "test description", "test impact", "safe evidence summary", "update configuration", null,
            WebCheckStatus.FindingDetected);
        return finding;
    }

    private WebAssessmentCheck Check(WebCheckStatus status)
        => new(tenantId, currentAssessmentId, "security-headers", "Security headers", "security-headers",
            status, "https://example.test/app");
}
