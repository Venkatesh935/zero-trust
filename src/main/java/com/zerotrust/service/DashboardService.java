package com.zerotrust.service;

import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.springframework.stereotype.Service;

import com.zerotrust.dto.DashboardDtos.DashboardSummary;
import com.zerotrust.dto.DashboardDtos.RiskDistribution;
import com.zerotrust.dto.MonitoringDtos.MonitoringDto;
import com.zerotrust.dto.PageResponse;
import com.zerotrust.dto.ScanSummaryDto;
import com.zerotrust.entity.MonitoringConfig;
import com.zerotrust.entity.RiskLevel;
import com.zerotrust.entity.Severity;
import com.zerotrust.entity.WebsiteTarget;
import com.zerotrust.repository.FindingRepository;
import com.zerotrust.repository.MonitoringConfigRepository;
import com.zerotrust.repository.ScanRecordRepository;
import com.zerotrust.repository.WebsiteTargetRepository;
import com.zerotrust.security.CurrentUserService;

/**
 * Dashboard statistics, computed from the database for the websites the
 * current user is authorized to see.
 */
@Service
public class DashboardService {

    private final WebsiteTargetRepository targets;
    private final ScanRecordRepository scans;
    private final FindingRepository findings;
    private final MonitoringConfigRepository monitoring;
    private final CurrentUserService currentUserService;
    private final ScanService scanService;

    public DashboardService(WebsiteTargetRepository targets, ScanRecordRepository scans, FindingRepository findings,
            MonitoringConfigRepository monitoring, CurrentUserService currentUserService, ScanService scanService) {
        this.targets = targets;
        this.scans = scans;
        this.findings = findings;
        this.monitoring = monitoring;
        this.currentUserService = currentUserService;
        this.scanService = scanService;
    }

    public DashboardSummary summary() {
        Optional<Set<Long>> allowed = currentUserService.accessibleTargetIds();
        List<WebsiteTarget> list = visibleTargets(allowed);
        List<Long> ids = list.stream().map(WebsiteTarget::getId).toList();

        long totalScans = allowed.isEmpty() ? scans.count() : (ids.isEmpty() ? 0 : scans.countByTargetIdIn(ids));
        long secure = 0;
        long attention = 0;
        long highRisk = 0;
        long unscanned = 0;
        int scoreSum = 0;
        int scored = 0;
        for (WebsiteTarget t : list) {
            Integer score = t.getLastScore();
            if (score == null) {
                unscanned++;
                continue;
            }
            scoreSum += score;
            scored++;
            if (score >= RiskLevel.GOOD.getMinScore()) {
                secure++;
            } else if (score >= RiskLevel.MODERATE.getMinScore()) {
                attention++;
            } else {
                highRisk++;
            }
        }

        Map<Severity, Long> severity = latestFindingCounts(list);
        List<MonitoringConfig> configs = allowed.isEmpty()
                ? monitoring.findAllByOrderByIdAsc()
                : (ids.isEmpty() ? List.of() : monitoring.findByTargetIdInOrderByIdAsc(ids));
        List<MonitoringDto> monitoringDtos = configs.stream().map(MonitoringDto::from).toList();
        long monitored = configs.stream().filter(MonitoringConfig::isEnabled).count();

        return new DashboardSummary(list.size(), totalScans, secure, attention, highRisk, unscanned,
                severity.get(Severity.CRITICAL), severity.get(Severity.HIGH), severity.get(Severity.MEDIUM),
                severity.get(Severity.LOW), severity.get(Severity.INFORMATIONAL),
                scored == 0 ? null : Math.round((float) scoreSum / scored), monitored, monitoringDtos);
    }

    public List<ScanSummaryDto> recentScans(int limit) {
        PageResponse<ScanSummaryDto> page = scanService.listScans(null, null, null, null, 0, limit);
        return page.content();
    }

    public RiskDistribution riskDistribution() {
        List<WebsiteTarget> list = visibleTargets(currentUserService.accessibleTargetIds());
        Map<String, Long> byLevel = new LinkedHashMap<>();
        for (RiskLevel level : RiskLevel.values()) {
            byLevel.put(level.getLabel(), 0L);
        }
        byLevel.put("Not scanned", 0L);
        for (WebsiteTarget t : list) {
            String key = t.getLastRiskLevel() == null ? "Not scanned" : t.getLastRiskLevel().getLabel();
            byLevel.merge(key, 1L, Long::sum);
        }
        Map<String, Long> bySeverity = new LinkedHashMap<>();
        latestFindingCounts(list).forEach((s, c) -> bySeverity.put(s.name(), c));
        return new RiskDistribution(byLevel, bySeverity);
    }

    private List<WebsiteTarget> visibleTargets(Optional<Set<Long>> allowed) {
        return allowed.isEmpty() ? targets.findAllByOrderByNameAsc() : targets.findAllById(allowed.get());
    }

    /** Failed-check counts by severity in each website's latest completed scan. */
    private Map<Severity, Long> latestFindingCounts(List<WebsiteTarget> list) {
        Map<Severity, Long> counts = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            counts.put(s, 0L);
        }
        List<Long> scanIds = list.stream().map(WebsiteTarget::getLastScanId).filter(Objects::nonNull).toList();
        if (!scanIds.isEmpty()) {
            for (Object[] row : findings.countFailedBySeverity(scanIds)) {
                counts.put((Severity) row[0], ((Number) row[1]).longValue());
            }
        }
        return counts;
    }
}
