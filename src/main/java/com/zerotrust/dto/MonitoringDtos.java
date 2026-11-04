package com.zerotrust.dto;

import java.time.Instant;
import java.util.List;

import com.zerotrust.entity.MonitoringConfig;
import com.zerotrust.entity.MonitoringEvent;
import com.zerotrust.entity.MonitoringState;
import com.zerotrust.entity.RiskLevel;

import jakarta.validation.constraints.NotNull;

public final class MonitoringDtos {

    private MonitoringDtos() {
    }

    public record MonitoringRequest(
            @NotNull(message = "websiteId is required.") Long websiteId,
            @NotNull(message = "intervalMinutes is required.") Integer intervalMinutes,
            Boolean enabled) {
    }

    public record MonitoringUpdateRequest(Integer intervalMinutes, Boolean enabled) {
    }

    public record MonitoringDto(Long id, Long websiteId, String websiteName, String websiteUrl, boolean enabled,
            int intervalMinutes, Instant lastRunAt, Instant nextRunAt, MonitoringState lastState,
            Integer lastScore, RiskLevel lastRiskLevel, int consecutiveFailures, Instant createdAt) {

        public static MonitoringDto from(MonitoringConfig c) {
            return new MonitoringDto(c.getId(), c.getTarget().getId(), c.getTarget().getName(), c.getTarget().getUrl(),
                    c.isEnabled(), c.getIntervalMinutes(), c.getLastRunAt(), c.getNextRunAt(), c.getLastState(),
                    c.getTarget().getLastScore(), c.getTarget().getLastRiskLevel(), c.getConsecutiveFailures(),
                    c.getCreatedAt());
        }
    }

    public record MonitoringEventDto(Long id, Instant checkedAt, Long scanId, boolean available, Integer score,
            Integer previousScore, Integer scoreChange, Long tlsDaysRemaining, MonitoringState state,
            List<String> changes) {

        public static MonitoringEventDto from(MonitoringEvent e) {
            Integer delta = e.getScore() != null && e.getPreviousScore() != null
                    ? e.getScore() - e.getPreviousScore() : null;
            List<String> changes = e.getChanges() == null || e.getChanges().isBlank()
                    ? List.of() : List.of(e.getChanges().split("\n"));
            return new MonitoringEventDto(e.getId(), e.getCheckedAt(), e.getScan() != null ? e.getScan().getId() : null,
                    e.isAvailable(), e.getScore(), e.getPreviousScore(), delta, e.getTlsDaysRemaining(), e.getState(),
                    changes);
        }
    }
}
