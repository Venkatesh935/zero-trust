package com.zerotrust.service;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Service;

import com.zerotrust.dto.FindingDto;
import com.zerotrust.dto.PageResponse;
import com.zerotrust.entity.Finding;
import com.zerotrust.entity.FindingCategory;
import com.zerotrust.entity.Severity;
import com.zerotrust.entity.WebsiteTarget;
import com.zerotrust.exception.ApiException;
import com.zerotrust.repository.FindingRepository;
import com.zerotrust.repository.MongoQueries;
import com.zerotrust.repository.WebsiteTargetRepository;
import com.zerotrust.security.CurrentUserService;

/**
 * Searching security findings across scans with filters for website,
 * severity, category and scan date.
 */
@Service
public class FindingService {

    private final FindingRepository findings;
    private final WebsiteTargetRepository targets;
    private final CurrentUserService currentUserService;
    private final MongoOperations mongo;

    public FindingService(FindingRepository findings, WebsiteTargetRepository targets,
            CurrentUserService currentUserService, MongoOperations mongo) {
        this.mongo = mongo;
        this.findings = findings;
        this.targets = targets;
        this.currentUserService = currentUserService;
    }

    /**
     * @param latestOnly    only findings from each website's most recent completed scan (current posture)
     * @param includePassed include checks that passed
     */
    public PageResponse<FindingDto> search(Long websiteId, Severity severity, FindingCategory category,
            Instant from, Instant to, boolean latestOnly, boolean includePassed, int page, int size) {
        if (websiteId != null) {
            currentUserService.checkTargetAccess(websiteId);
        }
        Optional<Set<Long>> allowed = currentUserService.accessibleTargetIds();
        List<Long> latestScanIds = latestOnly ? latestScanIds(allowed) : List.of();

        Query query = new Query();
        if (websiteId != null) {
            query.addCriteria(Criteria.where("targetId").is(websiteId));
        }
        if (severity != null) {
            query.addCriteria(Criteria.where("severity").is(severity));
        }
        if (category != null) {
            query.addCriteria(Criteria.where("category").is(category));
        }
        if (from != null || to != null) {
            Criteria started = Criteria.where("scanStartedAt");
            if (from != null) {
                started = started.gte(from);
            }
            if (to != null) {
                started = started.lt(to);
            }
            query.addCriteria(started);
        }
        if (!includePassed) {
            query.addCriteria(Criteria.where("passed").is(false));
        }
        if (latestOnly) {
            query.addCriteria(Criteria.where("scan").in(latestScanIds));
        }
        allowed.ifPresent(ids -> query.addCriteria(Criteria.where("targetId").in(ids)));
        // Newest scans first; the UI highlights severity with colour-coded badges.
        PageRequest pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "scanStartedAt", "id"));
        return PageResponse.of(MongoQueries.page(mongo, query, pageable, Finding.class), FindingDto::from);
    }

    public FindingDto get(Long id) {
        Finding finding = findings.findById(id).orElseThrow(() -> ApiException.notFound("Finding not found."));
        currentUserService.checkTargetAccess(finding.getScan().getTarget().getId());
        return FindingDto.from(finding);
    }

    private List<Long> latestScanIds(Optional<Set<Long>> allowed) {
        List<WebsiteTarget> list = allowed.isPresent()
                ? targets.findAllById(allowed.get())
                : targets.findAll();
        return list.stream().map(WebsiteTarget::getLastScanId).filter(Objects::nonNull).toList();
    }
}
