package com.zerotrust.service;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.zerotrust.dto.WebsiteDtos.WebsiteDto;
import com.zerotrust.dto.WebsiteDtos.WebsiteRequest;
import com.zerotrust.entity.AppUser;
import com.zerotrust.entity.AuditAction;
import com.zerotrust.entity.MonitoringConfig;
import com.zerotrust.entity.Role;
import com.zerotrust.entity.WebsiteTarget;
import com.zerotrust.exception.ApiException;
import com.zerotrust.repository.AppUserRepository;
import com.zerotrust.repository.FindingRepository;
import com.zerotrust.repository.MonitoringConfigRepository;
import com.zerotrust.repository.MonitoringEventRepository;
import com.zerotrust.repository.ScanRecordRepository;
import com.zerotrust.repository.WebsiteTargetRepository;
import com.zerotrust.security.CurrentUserService;
import com.zerotrust.security.TargetUrlValidator;
import com.zerotrust.security.TargetUrlValidator.ValidatedUrl;

/**
 * Registration and management of authorized website targets. URLs are fully
 * validated (including DNS and IP range checks) at registration time, and the
 * administrator must confirm authorization to assess the site.
 */
@Service
public class WebsiteService {

    private final WebsiteTargetRepository targets;
    private final AppUserRepository users;
    private final MonitoringConfigRepository monitoring;
    private final MonitoringEventRepository monitoringEvents;
    private final ScanRecordRepository scans;
    private final FindingRepository findings;
    private final TargetUrlValidator urlValidator;
    private final CurrentUserService currentUserService;
    private final AuditService auditService;

    public WebsiteService(WebsiteTargetRepository targets, AppUserRepository users,
            MonitoringConfigRepository monitoring, MonitoringEventRepository monitoringEvents,
            ScanRecordRepository scans, FindingRepository findings, TargetUrlValidator urlValidator,
            CurrentUserService currentUserService, AuditService auditService) {
        this.monitoringEvents = monitoringEvents;
        this.scans = scans;
        this.findings = findings;
        this.targets = targets;
        this.users = users;
        this.monitoring = monitoring;
        this.urlValidator = urlValidator;
        this.currentUserService = currentUserService;
        this.auditService = auditService;
    }

    public List<WebsiteDto> list() {
        List<WebsiteTarget> list = currentUserService.isAdmin()
                ? targets.findAllByOrderByNameAsc()
                : targets.findAssignedTo(currentUserService.principal().getId());
        Map<Long, Boolean> monitored = monitoring
                .findByTargetIdInOrderByIdAsc(list.stream().map(WebsiteTarget::getId).toList()).stream()
                .collect(Collectors.toMap(c -> c.getTarget().getId(), MonitoringConfig::isEnabled));
        return list.stream().map(t -> WebsiteDto.from(t, monitored.getOrDefault(t.getId(), false))).toList();
    }

    public WebsiteDto get(Long id) {
        currentUserService.checkTargetAccess(id);
        return toDto(find(id));
    }

    public WebsiteDto create(WebsiteRequest request) {
        requireAuthorization(request);
        ValidatedUrl url = urlValidator.validate(request.url());
        String normalized = url.uri().toString();
        if (targets.existsByUrlIgnoreCase(normalized)) {
            throw ApiException.conflict("This website URL is already registered.");
        }
        AppUser admin = currentUserService.currentUser();
        WebsiteTarget target = new WebsiteTarget();
        apply(target, request, url);
        target.setCreatedBy(admin);
        targets.save(target);
        auditService.log(AuditAction.WEBSITE_CREATED,
                "Registered website '" + target.getName() + "' (" + normalized + ")", target.getId());
        return toDto(target);
    }

    public WebsiteDto update(Long id, WebsiteRequest request) {
        requireAuthorization(request);
        WebsiteTarget target = find(id);
        ValidatedUrl url = urlValidator.validate(request.url());
        String normalized = url.uri().toString();
        if (targets.existsByUrlIgnoreCaseAndIdNot(normalized, id)) {
            throw ApiException.conflict("This website URL is already registered.");
        }
        String oldUrl = target.getUrl();
        apply(target, request, url);
        targets.save(target);
        auditService.log(AuditAction.WEBSITE_UPDATED, "Updated website '" + target.getName() + "'"
                + (oldUrl.equals(normalized) ? "" : " URL changed from " + oldUrl + " to " + normalized), id);
        return toDto(target);
    }

    public void delete(Long id) {
        WebsiteTarget target = find(id);
        auditService.log(AuditAction.WEBSITE_DELETED,
                "Deleted website '" + target.getName() + "' (" + target.getUrl() + ") and its scan history", id);
        // MongoDB has no foreign keys, so the website's data is removed explicitly.
        monitoring.findByTargetId(id).ifPresent(config -> {
            monitoringEvents.deleteByConfigId(config.getId());
            monitoring.delete(config);
        });
        findings.deleteByTargetId(id);
        scans.deleteByTargetId(id);
        targets.delete(target);
    }

    private void apply(WebsiteTarget target, WebsiteRequest request, ValidatedUrl url) {
        target.setName(request.name().trim());
        target.setUrl(url.uri().toString());
        target.setHostname(url.host());
        target.setDescription(AuthService.blankToNull(request.description()));
        target.setAuthorizationConfirmed(true);
        target.setAuthorizationNote(AuthService.blankToNull(request.authorizationNote()));
        target.getAssignedAnalysts().clear();
        target.getAssignedAnalysts().addAll(resolveAnalysts(request.analystIds()));
    }

    private Set<AppUser> resolveAnalysts(List<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            return Set.of();
        }
        Set<Long> unique = new HashSet<>(ids);
        List<AppUser> found = users.findByIdIn(List.copyOf(unique));
        if (found.size() != unique.size()) {
            throw ApiException.badRequest("One or more selected analysts do not exist.");
        }
        Map<Long, AppUser> byId = found.stream().collect(Collectors.toMap(AppUser::getId, Function.identity()));
        for (AppUser user : byId.values()) {
            if (user.getRole() != Role.ANALYST) {
                throw ApiException.badRequest("Only ANALYST users can be assigned; administrators can access all websites.");
            }
        }
        return new HashSet<>(byId.values());
    }

    private static void requireAuthorization(WebsiteRequest request) {
        if (!request.authorizationConfirmed()) {
            throw ApiException.badRequest("You must confirm that you own or are authorized to assess this website.");
        }
    }

    WebsiteTarget find(Long id) {
        return targets.findById(id).orElseThrow(() -> ApiException.notFound("Website not found."));
    }

    private WebsiteDto toDto(WebsiteTarget target) {
        boolean monitored = monitoring.findByTargetId(target.getId()).map(MonitoringConfig::isEnabled).orElse(false);
        return WebsiteDto.from(target, monitored);
    }
}
