package com.zerotrust.dto;

import java.time.Instant;

import com.zerotrust.entity.RiskLevel;
import com.zerotrust.entity.ScanRecord;
import com.zerotrust.entity.ScanStatus;
import com.zerotrust.entity.ScanTrigger;

public record ScanSummaryDto(Long id, Long websiteId, String websiteName, String websiteUrl,
        ScanStatus status, ScanTrigger trigger, Instant startedAt, Instant completedAt,
        Integer score, RiskLevel riskLevel, String riskLabel, int totalFindings,
        int criticalCount, int highCount, int mediumCount, int lowCount, int infoCount,
        String initiatedBy) {

    public static ScanSummaryDto from(ScanRecord s) {
        return new ScanSummaryDto(s.getId(), s.getTarget().getId(), s.getTarget().getName(), s.getTarget().getUrl(),
                s.getStatus(), s.getTrigger(), s.getStartedAt(), s.getCompletedAt(), s.getScore(), s.getRiskLevel(),
                s.getRiskLevel() == null ? null : s.getRiskLevel().getLabel(), s.getTotalFindings(),
                s.getCriticalCount(), s.getHighCount(), s.getMediumCount(), s.getLowCount(), s.getInfoCount(),
                s.getInitiatedBy() != null ? s.getInitiatedBy().getUsername() : "monitoring-scheduler");
    }
}
