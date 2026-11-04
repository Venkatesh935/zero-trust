package com.zerotrust.dto;

import java.util.List;
import java.util.Map;

import com.zerotrust.dto.MonitoringDtos.MonitoringDto;

public final class DashboardDtos {

    private DashboardDtos() {
    }

    /**
     * Headline numbers. Website posture counts use each website's latest completed scan;
     * finding counts are the failed checks in those latest scans (current posture).
     */
    public record DashboardSummary(
            long totalWebsites,
            long totalScans,
            long secureWebsites,
            long attentionWebsites,
            long highRiskWebsites,
            long unscannedWebsites,
            long criticalFindings,
            long highFindings,
            long mediumFindings,
            long lowFindings,
            long infoFindings,
            Integer averageScore,
            long monitoredWebsites,
            List<MonitoringDto> monitoring) {
    }

    public record RiskDistribution(Map<String, Long> websitesByRiskLevel, Map<String, Long> findingsBySeverity) {
    }
}
