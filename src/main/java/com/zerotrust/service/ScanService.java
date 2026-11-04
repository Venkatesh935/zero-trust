package com.zerotrust.service;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Service;

import com.zerotrust.config.ZeroTrustProperties;
import com.zerotrust.dto.FindingDto;
import com.zerotrust.dto.PageResponse;
import com.zerotrust.dto.ScanResponse;
import com.zerotrust.dto.ScanSummaryDto;
import com.zerotrust.entity.AppUser;
import com.zerotrust.entity.AuditAction;
import com.zerotrust.entity.Finding;
import com.zerotrust.entity.ScanRecord;
import com.zerotrust.entity.ScanStatus;
import com.zerotrust.entity.ScanTrigger;
import com.zerotrust.entity.Severity;
import com.zerotrust.entity.WebsiteTarget;
import com.zerotrust.exception.ApiException;
import com.zerotrust.exception.UnsafeTargetException;
import com.zerotrust.repository.FindingRepository;
import com.zerotrust.repository.MongoQueries;
import com.zerotrust.repository.ScanRecordRepository;
import com.zerotrust.repository.WebsiteTargetRepository;
import com.zerotrust.security.CurrentUserService;
import com.zerotrust.service.RiskScoringService.RiskResult;
import com.zerotrust.service.scanner.FindingDraft;
import com.zerotrust.service.scanner.ScanAssessment;

/**
 * Runs scans of registered targets and stores their results.
 *
 * <p>The scan record is saved as RUNNING first, the passive checks run, and
 * the results are written afterwards, so an interrupted scan stays visible and
 * is marked FAILED on restart. Only one scan per website can run at a time, and
 * manual scans of the same website are rate-limited.</p>
 */
@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final ScanRecordRepository scans;
    private final FindingRepository findings;
    private final WebsiteTargetRepository targets;
    private final WebsiteScannerService scanner;
    private final RiskScoringService scoring;
    private final AuditService auditService;
    private final CurrentUserService currentUserService;
    private final MongoOperations mongo;
    private final ZeroTrustProperties properties;

    private final Set<Long> runningTargets = ConcurrentHashMap.newKeySet();
    private final Map<Long, Instant> lastManualScan = new ConcurrentHashMap<>();

    public ScanService(ScanRecordRepository scans, FindingRepository findings, WebsiteTargetRepository targets,
            WebsiteScannerService scanner, RiskScoringService scoring, AuditService auditService,
            CurrentUserService currentUserService, MongoOperations mongo,
            ZeroTrustProperties properties) {
        this.scans = scans;
        this.findings = findings;
        this.targets = targets;
        this.scanner = scanner;
        this.scoring = scoring;
        this.auditService = auditService;
        this.currentUserService = currentUserService;
        this.mongo = mongo;
        this.properties = properties;
    }

    /** Starts a scan requested by the current user (ADMIN, or an ANALYST assigned to the website). */
    public ScanResponse startManualScan(Long targetId) {
        currentUserService.checkTargetAccess(targetId);
        WebsiteTarget target = targets.findById(targetId)
                .orElseThrow(() -> ApiException.notFound("Website not found."));
        if (!target.isAuthorizationConfirmed()) {
            throw ApiException.forbidden("Scanning requires confirmed authorization for this website.");
        }
        Instant now = Instant.now();
        Duration cooldown = Duration.ofSeconds(properties.getScanner().getManualScanCooldownSeconds());
        Instant last = lastManualScan.get(targetId);
        if (last != null && last.plus(cooldown).isAfter(now)) {
            long wait = Duration.between(now, last.plus(cooldown)).toSeconds() + 1;
            throw ApiException.tooManyRequests("This website was scanned moments ago. Please wait " + wait
                    + " seconds before scanning it again.");
        }
        lastManualScan.put(targetId, now);
        ScanRecord record = runScan(target, currentUserService.currentUser(), ScanTrigger.MANUAL);
        return getScan(record.getId());
    }

    /**
     * Executes a passive scan of a registered target. Used by manual scans and the
     * monitoring scheduler; the URL always comes from the stored target.
     */
    public ScanRecord runScan(WebsiteTarget target, AppUser initiatedBy, ScanTrigger trigger) {
        Long targetId = target.getId();
        if (!runningTargets.add(targetId)) {
            throw ApiException.conflict("A scan of this website is already in progress.");
        }
        try {
            ScanRecord record = new ScanRecord();
            record.setTarget(target);
            record.setInitiatedBy(initiatedBy);
            record.setTrigger(trigger);
            record.setStatus(ScanStatus.RUNNING);
            record.setStartedAt(Instant.now());
            record.setScannedUrl(target.getUrl());
            ScanRecord saved = scans.save(record);
            auditService.log(AuditAction.SCAN_STARTED,
                    trigger + " scan #" + saved.getId() + " started for " + target.getUrl(), targetId);

            ScanAssessment assessment;
            try {
                assessment = scanner.assess(target.getUrl(), saved);
            } catch (UnsafeTargetException e) {
                assessment = ScanAssessment.unreachable("Blocked by SSRF protection: " + e.getMessage());
            } catch (RuntimeException e) {
                log.error("Scanner error for target {}", targetId, e);
                assessment = ScanAssessment.unreachable("Unexpected scanner error.");
            }

            ScanAssessment result = assessment;
            ScanRecord completed = persistResult(saved, targetId, result);
            if (completed.getStatus() == ScanStatus.COMPLETED) {
                auditService.log(AuditAction.SCAN_COMPLETED, "Scan #" + completed.getId() + " completed: score "
                        + completed.getScore() + " (" + completed.getRiskLevel().getLabel() + "), "
                        + completed.getTotalFindings() + " findings", targetId);
            } else {
                auditService.log(AuditAction.SCAN_FAILED,
                        "Scan #" + completed.getId() + " failed: " + completed.getErrorMessage(), targetId);
            }
            return completed;
        } finally {
            runningTargets.remove(targetId);
        }
    }

    private ScanRecord persistResult(ScanRecord record, Long targetId, ScanAssessment assessment) {
        record.setCompletedAt(Instant.now());
        if (!assessment.reachable()) {
            record.setStatus(ScanStatus.FAILED);
            record.setErrorMessage(AuditService.sanitize(assessment.errorMessage(), 1000));
        } else {
            RiskResult risk = scoring.calculate(assessment.findings());
            record.setStatus(ScanStatus.COMPLETED);
            record.setScore(risk.score());
            record.setRiskLevel(risk.riskLevel());
            record.setTotalFindings(risk.totalFindings());
            record.setCriticalCount(risk.count(Severity.CRITICAL));
            record.setHighCount(risk.count(Severity.HIGH));
            record.setMediumCount(risk.count(Severity.MEDIUM));
            record.setLowCount(risk.count(Severity.LOW));
            record.setInfoCount(risk.count(Severity.INFORMATIONAL));
        }
        ScanRecord managed = scans.save(record);

        List<Finding> entities = new ArrayList<>();
        for (FindingDraft draft : assessment.findings()) {
            Finding f = new Finding();
            f.setScan(managed);
            f.setCategory(draft.category());
            f.setCheckKey(draft.checkKey());
            f.setTitle(draft.title());
            f.setDescription(draft.description());
            f.setSeverity(draft.severity());
            f.setPassed(draft.passed());
            f.setEvidence(draft.evidence());
            f.setRecommendation(draft.recommendation());
            entities.add(f);
        }
        findings.saveAll(entities);

        WebsiteTarget target = targets.findById(targetId).orElse(null);
        if (target != null) {
            target.setLastScanStatus(managed.getStatus());
            target.setLastScanAt(managed.getStartedAt());
            if (managed.getStatus() == ScanStatus.COMPLETED) {
                target.setLastScanId(managed.getId());
                target.setLastScore(managed.getScore());
                target.setLastRiskLevel(managed.getRiskLevel());
            }
            targets.save(target);
        }
        return managed;
    }

    public ScanResponse getScan(Long id) {
        ScanRecord scan = scans.findById(id).orElseThrow(() -> ApiException.notFound("Scan not found."));
        currentUserService.checkTargetAccess(scan.getTarget().getId());
        List<Finding> list = findings.findByScanIdOrderByIdAsc(id);
        List<FindingDto> dtos = sortForDisplay(list).stream().map(FindingDto::from).toList();
        RiskResult risk = scan.getStatus() == ScanStatus.COMPLETED ? scoring.calculate(list) : null;
        return ScanResponse.from(scan, dtos, risk);
    }

    public List<FindingDto> getScanFindings(Long id) {
        ScanRecord scan = scans.findById(id).orElseThrow(() -> ApiException.notFound("Scan not found."));
        currentUserService.checkTargetAccess(scan.getTarget().getId());
        return sortForDisplay(findings.findByScanIdOrderByIdAsc(id)).stream().map(FindingDto::from).toList();
    }

    public PageResponse<ScanSummaryDto> listScans(Long websiteId, ScanStatus status, Instant from, Instant to,
            int page, int size) {
        if (websiteId != null) {
            currentUserService.checkTargetAccess(websiteId);
        }
        Optional<Set<Long>> allowed = currentUserService.accessibleTargetIds();
        Query query = new Query();
        if (websiteId != null) {
            query.addCriteria(Criteria.where("target").is(websiteId));
        }
        if (status != null) {
            query.addCriteria(Criteria.where("status").is(status));
        }
        if (from != null || to != null) {
            Criteria started = Criteria.where("startedAt");
            if (from != null) {
                started = started.gte(from);
            }
            if (to != null) {
                started = started.lt(to);
            }
            query.addCriteria(started);
        }
        allowed.ifPresent(ids -> query.addCriteria(Criteria.where("target").in(ids)));
        PageRequest pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "startedAt", "id"));
        return PageResponse.of(MongoQueries.page(mongo, query, pageable, ScanRecord.class), ScanSummaryDto::from);
    }

    /** Failed checks first (most severe first), then passed checks, grouped by category. */
    static List<Finding> sortForDisplay(List<Finding> list) {
        return list.stream().sorted(Comparator
                .comparing(Finding::isPassed)
                .thenComparing(f -> f.getSeverity().ordinal())
                .thenComparing(f -> f.getCategory().ordinal())).toList();
    }
}
