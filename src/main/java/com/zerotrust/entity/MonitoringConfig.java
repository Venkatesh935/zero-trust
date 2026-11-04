package com.zerotrust.entity;

import java.time.Instant;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.DocumentReference;

/**
 * Continuous monitoring settings for a registered website. Scheduled jobs
 * only ever scan the URL of the linked target, never user-supplied URLs.
 */
@Document("monitoring_configs")
public class MonitoringConfig extends Timestamped {

    @Indexed(unique = true)
    @DocumentReference
    private WebsiteTarget target;

    private boolean enabled = true;

    private int intervalMinutes;

    private Instant lastRunAt;

    private Instant nextRunAt;

    private MonitoringState lastState = MonitoringState.PENDING;

    private int consecutiveFailures;

    @DocumentReference
    private AppUser createdBy;

    public WebsiteTarget getTarget() {
        return target;
    }

    public void setTarget(WebsiteTarget target) {
        this.target = target;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getIntervalMinutes() {
        return intervalMinutes;
    }

    public void setIntervalMinutes(int intervalMinutes) {
        this.intervalMinutes = intervalMinutes;
    }

    public Instant getLastRunAt() {
        return lastRunAt;
    }

    public void setLastRunAt(Instant lastRunAt) {
        this.lastRunAt = lastRunAt;
    }

    public Instant getNextRunAt() {
        return nextRunAt;
    }

    public void setNextRunAt(Instant nextRunAt) {
        this.nextRunAt = nextRunAt;
    }

    public MonitoringState getLastState() {
        return lastState;
    }

    public void setLastState(MonitoringState lastState) {
        this.lastState = lastState;
    }

    public int getConsecutiveFailures() {
        return consecutiveFailures;
    }

    public void setConsecutiveFailures(int consecutiveFailures) {
        this.consecutiveFailures = consecutiveFailures;
    }

    public AppUser getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(AppUser createdBy) {
        this.createdBy = createdBy;
    }
}
