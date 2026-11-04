package com.zerotrust.entity;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.DocumentReference;

/**
 * A website that an administrator has registered and explicitly confirmed
 * as authorized for passive security assessment.
 */
@Document("website_targets")
public class WebsiteTarget extends Timestamped {

    private String name;

    @Indexed(unique = true)
    private String url;

    @Indexed
    private String hostname;

    private String description;

    private boolean authorizationConfirmed;

    private String authorizationNote;

    @DocumentReference
    private AppUser createdBy;

    /** Analysts the administrator has explicitly granted access to this target. */
        @DocumentReference
    private Set<AppUser> assignedAnalysts = new LinkedHashSet<>();

    private Long lastScanId;

    private Integer lastScore;

    private RiskLevel lastRiskLevel;

    private ScanStatus lastScanStatus;

    private Instant lastScanAt;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isAuthorizationConfirmed() {
        return authorizationConfirmed;
    }

    public void setAuthorizationConfirmed(boolean authorizationConfirmed) {
        this.authorizationConfirmed = authorizationConfirmed;
    }

    public String getAuthorizationNote() {
        return authorizationNote;
    }

    public void setAuthorizationNote(String authorizationNote) {
        this.authorizationNote = authorizationNote;
    }

    public AppUser getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(AppUser createdBy) {
        this.createdBy = createdBy;
    }

    public Set<AppUser> getAssignedAnalysts() {
        return assignedAnalysts;
    }

    public Long getLastScanId() {
        return lastScanId;
    }

    public void setLastScanId(Long lastScanId) {
        this.lastScanId = lastScanId;
    }

    public Integer getLastScore() {
        return lastScore;
    }

    public void setLastScore(Integer lastScore) {
        this.lastScore = lastScore;
    }

    public RiskLevel getLastRiskLevel() {
        return lastRiskLevel;
    }

    public void setLastRiskLevel(RiskLevel lastRiskLevel) {
        this.lastRiskLevel = lastRiskLevel;
    }

    public ScanStatus getLastScanStatus() {
        return lastScanStatus;
    }

    public void setLastScanStatus(ScanStatus lastScanStatus) {
        this.lastScanStatus = lastScanStatus;
    }

    public Instant getLastScanAt() {
        return lastScanAt;
    }

    public void setLastScanAt(Instant lastScanAt) {
        this.lastScanAt = lastScanAt;
    }
}
