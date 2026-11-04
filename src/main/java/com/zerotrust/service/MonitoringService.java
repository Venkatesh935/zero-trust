package com.zerotrust.service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.zerotrust.config.ZeroTrustProperties;
import com.zerotrust.dto.MonitoringDtos.MonitoringDto;
import com.zerotrust.dto.MonitoringDtos.MonitoringEventDto;
import com.zerotrust.dto.MonitoringDtos.MonitoringRequest;
import com.zerotrust.dto.MonitoringDtos.MonitoringUpdateRequest;
import com.zerotrust.dto.PageResponse;
import com.zerotrust.entity.AuditAction;
import com.zerotrust.entity.MonitoringConfig;
import com.zerotrust.entity.MonitoringEvent;
import com.zerotrust.entity.MonitoringState;
import com.zerotrust.entity.ScanRecord;
import com.zerotrust.entity.ScanStatus;
import com.zerotrust.entity.ScanTrigger;
import com.zerotrust.entity.WebsiteTarget;
import com.zerotrust.exception.ApiException;
import com.zerotrust.repository.FindingRepository;
import com.zerotrust.repository.MonitoringConfigRepository;
import com.zerotrust.repository.MonitoringEventRepository;
import com.zerotrust.repository.ScanRecordRepository;
import com.zerotrust.repository.WebsiteTargetRepository;
import com.zerotrust.security.CurrentUserService;
import com.zerotrust.service.MonitoringComparator.Comparison;

/**
 * Continuous monitoring: scheduled passive scans of registered websites with
 * change detection against the previous scan.
 */
@Service
public class MonitoringService {

    private static final Logger log = LoggerFactory.getLogger(MonitoringService.class);

    private final MonitoringConfigRepository configs;
    private final MonitoringEventRepository events;
    private final WebsiteTargetRepository targets;
    private final ScanRecordRepository scans;
    private final FindingRepository findings;
    private final ScanService scanService;
    private final MonitoringComparator comparator;
    private final CurrentUserService currentUserService;
    private final AuditService auditService;
    private final ZeroTrustProperties properties;

    public MonitoringService(MonitoringConfigRepository configs, MonitoringEventRepository events,
            WebsiteTargetRepository targets, ScanRecordRepository scans, FindingRepository findings,
            ScanService scanService, MonitoringComparator comparator, CurrentUserService currentUserService,
            AuditService auditService, ZeroTrustProperties properties) {
        this.configs = configs;
        this.events = events;
        this.targets = targets;
        this.scans = scans;
        this.findings = findings;
        this.scanService = scanService;
        this.comparator = comparator;
        this.currentUserService = currentUserService;
        this.auditService = auditService;
        this.properties = properties;
    }

    public List<MonitoringDto> list() {
        Optional<Set<Long>> allowed = currentUserService.accessibleTargetIds();
        List<MonitoringConfig> list = allowed.isEmpty() ? configs.findAllByOrderByIdAsc()
                : (allowed.get().isEmpty() ? List.of() : configs.findByTargetIdInOrderByIdAsc(allowed.get()));
        return list.stream().map(MonitoringDto::from).toList();
    }

    public MonitoringDto create(MonitoringRequest request) {
        WebsiteTarget target = targets.findById(request.websiteId())
                .orElseThrow(() -> ApiException.notFound("Website not found."));
        if (configs.existsByTargetId(target.getId())) {
            throw ApiException.conflict("Monitoring is already configured for this website. Edit it instead.");
        }
        int interval = validateInterval(request.intervalMinutes());
        MonitoringConfig config = new MonitoringConfig();
        config.setTarget(target);
        config.setIntervalMinutes(interval);
        config.setEnabled(request.enabled() == null || request.enabled());
        config.setNextRunAt(config.isEnabled() ? Instant.now() : null);
        config.setCreatedBy(currentUserService.currentUser());
        configs.save(config);
        auditService.log(AuditAction.MONITORING_CREATED, "Monitoring " + (config.isEnabled() ? "enabled" : "created (disabled)")
                + " for '" + target.getName() + "' every " + interval + " minutes", target.getId());
        return MonitoringDto.from(config);
    }

    public MonitoringDto update(Long id, MonitoringUpdateRequest request) {
        MonitoringConfig config = find(id);
        StringBuilder changes = new StringBuilder();
        if (request.intervalMinutes() != null && request.intervalMinutes() != config.getIntervalMinutes()) {
            config.setIntervalMinutes(validateInterval(request.intervalMinutes()));
            changes.append(" interval ").append(config.getIntervalMinutes()).append(" min;");
            if (config.isEnabled() && config.getLastRunAt() != null) {
                config.setNextRunAt(config.getLastRunAt().plus(Duration.ofMinutes(config.getIntervalMinutes())));
            }
        }
        if (request.enabled() != null && request.enabled() != config.isEnabled()) {
            config.setEnabled(request.enabled());
            changes.append(request.enabled() ? " enabled;" : " disabled;");
            config.setNextRunAt(request.enabled() ? Instant.now() : null);
        }
        configs.save(config);
        auditService.log(AuditAction.MONITORING_UPDATED, "Monitoring for '" + config.getTarget().getName() + "' updated:"
                + (changes.isEmpty() ? " no changes" : changes.toString()), config.getTarget().getId());
        return MonitoringDto.from(config);
    }

    public void delete(Long id) {
        MonitoringConfig config = find(id);
        auditService.log(AuditAction.MONITORING_DELETED,
                "Monitoring removed for '" + config.getTarget().getName() + "'", config.getTarget().getId());
        events.deleteByConfigId(config.getId());
        configs.delete(config);
    }

    public PageResponse<MonitoringEventDto> history(Long id, int page, int size) {
        MonitoringConfig config = find(id);
        currentUserService.checkTargetAccess(config.getTarget().getId());
        return PageResponse.of(events.findByConfigIdOrderByCheckedAtDesc(id, PageRequest.of(page, size)),
                MonitoringEventDto::from);
    }

    /** Runs a monitoring check immediately (administrator action). */
    public MonitoringEventDto runNow(Long id) {
        MonitoringConfig config = configs.findById(id)
                .orElseThrow(() -> ApiException.notFound("Monitoring configuration not found."));
        return MonitoringEventDto.from(runCheck(config));
    }

    /** Called by the scheduler: runs a limited number of due checks per cycle. */
    public int runDueChecks() {
        List<MonitoringConfig> due = configs.findByEnabledTrueAndNextRunAtLessThanEqualOrderByNextRunAtAsc(
                Instant.now(), PageRequest.of(0, properties.getMonitoring().getMaxChecksPerCycle()));
        int done = 0;
        for (MonitoringConfig config : due) {
            try {
                runCheck(config);
                done++;
            } catch (ApiException e) {
                log.info("Monitoring check for target {} skipped: {}", config.getTarget().getId(), e.getMessage());
                reschedule(config.getId());
            } catch (RuntimeException e) {
                log.error("Monitoring check for target {} failed", config.getTarget().getId(), e);
                reschedule(config.getId());
            }
        }
        return done;
    }

    private MonitoringEvent runCheck(MonitoringConfig config) {
        WebsiteTarget target = config.getTarget();
        // The URL always comes from the registered target, never from user input.
        ScanRecord scan = scanService.runScan(target, null, ScanTrigger.SCHEDULED);

        ScanRecord previous = scans.findFirstByTargetIdAndIdLessThanOrderByIdDesc(target.getId(), scan.getId())
                .orElse(null);
        Comparison comparison = comparator.compare(previous,
                previous == null ? List.of() : findings.findByScanIdOrderByIdAsc(previous.getId()),
                scan, findings.findByScanIdOrderByIdAsc(scan.getId()));

        MonitoringConfig managed = configs.findById(config.getId()).orElseThrow();
        MonitoringEvent event = new MonitoringEvent();
        event.setConfig(managed);
        event.setScan(scan);
        event.setCheckedAt(Instant.now());
        event.setAvailable(scan.getStatus() == ScanStatus.COMPLETED);
        event.setScore(scan.getScore());
        event.setPreviousScore(previous != null ? previous.getScore() : null);
        event.setTlsDaysRemaining(scan.getTlsDaysRemaining());
        event.setState(comparison.state());
        event.setChanges(AuditService.sanitizeLines(String.join("\n", comparison.changes()), 4000));
        events.save(event);

        Instant now = Instant.now();
        managed.setLastRunAt(now);
        managed.setLastState(comparison.state());
        managed.setConsecutiveFailures(event.isAvailable() ? 0 : managed.getConsecutiveFailures() + 1);
        managed.setNextRunAt(managed.isEnabled() ? now.plus(Duration.ofMinutes(managed.getIntervalMinutes())) : null);
        configs.save(managed);

        if (comparison.state() == MonitoringState.DEGRADED || comparison.state() == MonitoringState.UNAVAILABLE) {
            auditService.log(AuditAction.MONITORING_ALERT, "Monitoring alert for '" + target.getName() + "' ("
                    + comparison.state() + "): " + String.join("; ", comparison.changes()), target.getId());
        }
        return event;
    }

    private void reschedule(Long configId) {
        configs.findById(configId).ifPresent(c -> {
            c.setNextRunAt(Instant.now().plus(Duration.ofMinutes(Math.max(1, properties.getMonitoring().getMinIntervalMinutes()))));
            configs.save(c);
        });
    }

    private int validateInterval(Integer minutes) {
        int min = properties.getMonitoring().getMinIntervalMinutes();
        int max = properties.getMonitoring().getMaxIntervalMinutes();
        if (minutes == null || minutes < min || minutes > max) {
            throw ApiException.badRequest("Monitoring interval must be between " + min + " and " + max + " minutes.");
        }
        return minutes;
    }

    private MonitoringConfig find(Long id) {
        return configs.findById(id)
                .orElseThrow(() -> ApiException.notFound("Monitoring configuration not found."));
    }
}
