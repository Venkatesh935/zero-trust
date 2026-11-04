package com.zerotrust.entity;

import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.DocumentReference;
import java.time.Instant;

/**
 * Result of one security check within a scan. Passed checks are stored too
 * (with {@code passed = true}) so that reports can show the full assessment;
 * only failed checks count as findings in the risk score.
 */
@Document("findings")
public class Finding extends LongIdEntity implements ScorableFinding {

    @Indexed
    @DocumentReference
    private ScanRecord scan;

    /** Denormalized from the scan so findings can be filtered and sorted without joins. */
    @Indexed
    private Long targetId;

    private Instant scanStartedAt;

    @Indexed
    private FindingCategory category;

    /** Stable identifier of the check, used to compare scans over time. */
    private String checkKey;

    private String title;

    private String description;

    @Indexed
    private Severity severity;

    private boolean passed;

    private String evidence;

    private String recommendation;

    public ScanRecord getScan() {
        return scan;
    }

    public void setScan(ScanRecord scan) {
        this.scan = scan;
        this.targetId = scan.getTarget().getId();
        this.scanStartedAt = scan.getStartedAt();
    }

    public Long getTargetId() {
        return targetId;
    }

    public Instant getScanStartedAt() {
        return scanStartedAt;
    }

    @Override
    public FindingCategory getCategory() {
        return category;
    }

    public void setCategory(FindingCategory category) {
        this.category = category;
    }

    @Override
    public String getCheckKey() {
        return checkKey;
    }

    public void setCheckKey(String checkKey) {
        this.checkKey = checkKey;
    }

    @Override
    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    @Override
    public boolean isPassed() {
        return passed;
    }

    public void setPassed(boolean passed) {
        this.passed = passed;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }
}
