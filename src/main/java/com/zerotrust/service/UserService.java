package com.zerotrust.service;

import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.zerotrust.dto.AuthDtos.UserCreateRequest;
import com.zerotrust.dto.AuthDtos.UserDto;
import com.zerotrust.dto.AuthDtos.UserUpdateRequest;
import com.zerotrust.entity.AppUser;
import com.zerotrust.entity.AuditAction;
import com.zerotrust.entity.Role;
import com.zerotrust.entity.WebsiteTarget;
import com.zerotrust.exception.ApiException;
import com.zerotrust.repository.AppUserRepository;
import com.zerotrust.repository.WebsiteTargetRepository;
import com.zerotrust.security.CurrentUserService;
import com.zerotrust.util.PasswordPolicy;

/**
 * Administrator user management. Guards against locking everyone out:
 * an administrator cannot delete, disable or demote their own account, and
 * the last enabled administrator cannot be removed.
 */
@Service
public class UserService {

    private final AppUserRepository users;
    private final WebsiteTargetRepository targets;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;
    private final CurrentUserService currentUserService;

    public UserService(AppUserRepository users, WebsiteTargetRepository targets, PasswordEncoder passwordEncoder,
            AuditService auditService, CurrentUserService currentUserService) {
        this.users = users;
        this.targets = targets;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
        this.currentUserService = currentUserService;
    }

    public List<UserDto> list() {
        return users.findAllByOrderByUsernameAsc().stream().map(UserDto::from).toList();
    }

    public UserDto create(UserCreateRequest request) {
        String username = request.username().trim();
        if (users.existsByUsernameIgnoreCase(username)) {
            throw ApiException.conflict("Username is already taken.");
        }
        PasswordPolicy.validate(request.password(), username);
        AppUser user = new AppUser();
        user.setUsername(username);
        user.setFullName(AuthService.blankToNull(request.fullName()));
        user.setEmail(AuthService.blankToNull(request.email()));
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setRole(request.role() == null ? Role.ANALYST : request.role());
        user.setEnabled(request.enabled() == null || request.enabled());
        users.save(user);
        auditService.log(AuditAction.USER_CREATED,
                "Created user '" + username + "' with role " + user.getRole(), null);
        return UserDto.from(user);
    }

    public UserDto update(Long id, UserUpdateRequest request) {
        AppUser user = users.findById(id).orElseThrow(() -> ApiException.notFound("User not found."));
        boolean self = id.equals(currentUserService.principal().getId());
        StringBuilder changes = new StringBuilder();

        if (request.fullName() != null) {
            user.setFullName(AuthService.blankToNull(request.fullName()));
        }
        if (request.email() != null) {
            user.setEmail(AuthService.blankToNull(request.email()));
        }
        if (request.role() != null && request.role() != user.getRole()) {
            if (self) {
                throw ApiException.badRequest("You cannot change your own role.");
            }
            if (user.getRole() == Role.ADMIN) {
                ensureAnotherAdmin();
            }
            changes.append(" role ").append(user.getRole()).append("->").append(request.role()).append(';');
            user.setRole(request.role());
            if (request.role() == Role.ADMIN) {
                // administrators see all targets; explicit assignments are no longer needed
                removeAssignments(user);
            }
        }
        if (request.enabled() != null && request.enabled() != user.isEnabled()) {
            if (self && !request.enabled()) {
                throw ApiException.badRequest("You cannot disable your own account.");
            }
            if (!request.enabled() && user.getRole() == Role.ADMIN) {
                ensureAnotherAdmin();
            }
            changes.append(request.enabled() ? " enabled;" : " disabled;");
            user.setEnabled(request.enabled());
        }
        if (request.password() != null && !request.password().isBlank()) {
            PasswordPolicy.validate(request.password(), user.getUsername());
            user.setPasswordHash(passwordEncoder.encode(request.password()));
            changes.append(" password reset;");
        }
        if (Boolean.TRUE.equals(request.unlock())) {
            user.setLockedUntil(null);
            user.setFailedLoginAttempts(0);
            changes.append(" unlocked;");
        }
        users.save(user);
        auditService.log(AuditAction.USER_UPDATED, "Updated user '" + user.getUsername() + "':"
                + (changes.isEmpty() ? " profile details" : changes.toString()), null);
        return UserDto.from(user);
    }

    public void delete(Long id) {
        AppUser user = users.findById(id).orElseThrow(() -> ApiException.notFound("User not found."));
        if (id.equals(currentUserService.principal().getId())) {
            throw ApiException.badRequest("You cannot delete your own account.");
        }
        if (user.getRole() == Role.ADMIN && user.isEnabled()) {
            ensureAnotherAdmin();
        }
        removeAssignments(user);
        auditService.log(AuditAction.USER_DELETED, "Deleted user '" + user.getUsername() + "'", null);
        users.delete(user);
    }

    private void removeAssignments(AppUser user) {
        for (WebsiteTarget target : targets.findAssignedTo(user.getId())) {
            target.getAssignedAnalysts().removeIf(a -> a.getId().equals(user.getId()));
            targets.save(target);
        }
    }

    private void ensureAnotherAdmin() {
        if (users.countByRoleAndEnabledTrue(Role.ADMIN) <= 1) {
            throw ApiException.badRequest("At least one enabled administrator must remain.");
        }
    }
}
