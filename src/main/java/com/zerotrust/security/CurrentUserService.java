package com.zerotrust.security;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.zerotrust.entity.AppUser;
import com.zerotrust.entity.AuditAction;
import com.zerotrust.exception.ApiException;
import com.zerotrust.repository.AppUserRepository;
import com.zerotrust.repository.WebsiteTargetRepository;
import com.zerotrust.service.AuditService;

/**
 * Resolves the current user and enforces per-website authorization:
 * administrators can access every target, analysts only the targets an
 * administrator explicitly assigned to them.
 */
@Service
public class CurrentUserService {

    private final AppUserRepository users;
    private final WebsiteTargetRepository targets;
    private final AuditService auditService;

    public CurrentUserService(AppUserRepository users, WebsiteTargetRepository targets, AuditService auditService) {
        this.users = users;
        this.targets = targets;
        this.auditService = auditService;
    }

    public Optional<UserPrincipal> optionalPrincipal() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof UserPrincipal principal) {
            return Optional.of(principal);
        }
        return Optional.empty();
    }

    public UserPrincipal principal() {
        return optionalPrincipal()
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Authentication required."));
    }

    public AppUser currentUser() {
        return users.findById(principal().getId())
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Authentication required."));
    }

    public boolean isAdmin() {
        return principal().isAdmin();
    }

    /** Target IDs the current user may access, or empty when the user may access all targets. */
    public Optional<Set<Long>> accessibleTargetIds() {
        UserPrincipal p = principal();
        if (p.isAdmin()) {
            return Optional.empty();
        }
        return Optional.of(new HashSet<>(targets.findIdsAssignedTo(p.getId())));
    }

    public void checkTargetAccess(Long targetId) {
        UserPrincipal p = principal();
        if (p.isAdmin() || targets.isAssigned(targetId, p.getId())) {
            return;
        }
        auditService.log(AuditAction.ACCESS_DENIED,
                "Attempted access to website target " + targetId + " without assignment", targetId);
        throw ApiException.forbidden("You are not authorized to access this website.");
    }
}
