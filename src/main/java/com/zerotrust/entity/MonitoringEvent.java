package com.zerotrust.entity;

import java.time.Instant;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.mapping.DocumentReference;

/**
 * One monitoring check: the scan it produced and the changes detected
 * compared with the previous scan of the same website.
 */
@Document("monitoring_events")
@CompoundIndex(name = "idx_monitoring_events_config", def = "{'config': 1, 'checkedAt': -1}")
public class MonitoringEvent extends LongIdEntity {

    @DocumentReference
    private MonitoringConfig config;

    @DocumentReference
    private ScanRecord scan;

    private Instant checkedAt;

    private boolean available;

    private Integer score;

    private Integer previousScore;

    private Long tlsDaysRemaining;

    private MonitoringState state;

    /** Detected changes, one per line. */
    private String changes;

    public MonitoringConfig getConfig() {
        return config;
    }

    public void setConfig(MonitoringConfig config) {
        this.config = config;
    }

    public ScanRecord getScan() {
        return scan;
    }

    public void setScan(ScanRecord scan) {
        this.scan = scan;
    }

    public Instant getCheckedAt() {
        return checkedAt;
    }

    public void setCheckedAt(Instant checkedAt) {
        this.checkedAt = checkedAt;
    }

    public boolean isAvailable() {
        return available;
    }

    public void setAvailable(boolean available) {
        this.available = available;
    }

    public Integer getScore() {
        return score;
    }

    public void setScore(Integer score) {
        this.score = score;
    }

    public Integer getPreviousScore() {
        return previousScore;
    }

    public void setPreviousScore(Integer previousScore) {
        this.previousScore = previousScore;
    }

    public Long getTlsDaysRemaining() {
        return tlsDaysRemaining;
    }

    public void setTlsDaysRemaining(Long tlsDaysRemaining) {
        this.tlsDaysRemaining = tlsDaysRemaining;
    }

    public MonitoringState getState() {
        return state;
    }

    public void setState(MonitoringState state) {
        this.state = state;
    }

    public String getChanges() {
        return changes;
    }

    public void setChanges(String changes) {
        this.changes = changes;
    }
}
