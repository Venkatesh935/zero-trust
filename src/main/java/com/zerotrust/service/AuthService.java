package com.zerotrust.service;

import java.time.Duration;
import java.time.Instant;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;

import com.zerotrust.config.ZeroTrustProperties;
import com.zerotrust.dto.AuthDtos.ChangePasswordRequest;
import com.zerotrust.dto.AuthDtos.LoginRequest;
import com.zerotrust.dto.AuthDtos.RegisterRequest;
import com.zerotrust.entity.AppUser;
import com.zerotrust.entity.AuditAction;
import com.zerotrust.entity.Role;
import com.zerotrust.exception.ApiException;
import com.zerotrust.repository.AppUserRepository;
import com.zerotrust.security.CurrentUserService;
import com.zerotrust.security.UserPrincipal;
import com.zerotrust.util.PasswordPolicy;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Login, logout, self-registration and password changes. Repeated failed
 * logins lock the account temporarily to slow down password guessing.
 */
@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository contextRepository;
    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;
    private final SettingsService settingsService;
    private final CurrentUserService currentUserService;
    private final ZeroTrustProperties properties;

    public AuthService(AuthenticationManager authenticationManager, SecurityContextRepository contextRepository,
            AppUserRepository users, PasswordEncoder passwordEncoder, AuditService auditService,
            SettingsService settingsService, CurrentUserService currentUserService, ZeroTrustProperties properties) {
        this.authenticationManager = authenticationManager;
        this.contextRepository = contextRepository;
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
        this.settingsService = settingsService;
        this.currentUserService = currentUserService;
        this.properties = properties;
    }

    public AppUser login(LoginRequest request, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        String username = request.username().trim();
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(username, request.password()));
        } catch (LockedException e) {
            auditService.logForUser(null, username, AuditAction.LOGIN_FAILURE, "Login rejected: account locked", null);
            throw new ApiException(HttpStatus.UNAUTHORIZED,
                    "Account is temporarily locked after repeated failed logins. Try again later.");
        } catch (DisabledException e) {
            auditService.logForUser(null, username, AuditAction.LOGIN_FAILURE,
                    "Login rejected: account disabled or pending approval", null);
            throw new ApiException(HttpStatus.UNAUTHORIZED,
                    "Account is disabled or awaiting administrator approval.");
        } catch (BadCredentialsException e) {
            recordFailedAttempt(username);
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Invalid username or password.");
        } catch (AuthenticationException e) {
            auditService.logForUser(null, username, AuditAction.LOGIN_FAILURE, "Login failed", null);
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Authentication failed.");
        }

        UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();
        AppUser user = users.findById(principal.getId())
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Authentication failed."));
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        user.setLastLoginAt(Instant.now());
        users.save(user);

        // Session fixation protection: never reuse a pre-login session ID.
        if (httpRequest.getSession(false) != null) {
            httpRequest.changeSessionId();
        }
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        contextRepository.saveContext(context, httpRequest, httpResponse);

        auditService.log(AuditAction.LOGIN_SUCCESS, "User signed in", null);
        return user;
    }

    private void recordFailedAttempt(String username) {
        AppUser user = users.findByUsernameIgnoreCase(username).orElse(null);
        if (user == null) {
            auditService.logForUser(null, username, AuditAction.LOGIN_FAILURE, "Invalid credentials (unknown user)", null);
            return;
        }
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);
        int max = properties.getSecurity().getMaxFailedLogins();
        boolean locked = attempts >= max;
        if (locked) {
            user.setLockedUntil(Instant.now().plus(Duration.ofMinutes(properties.getSecurity().getLockoutMinutes())));
            user.setFailedLoginAttempts(0);
        }
        users.save(user);
        auditService.logForUser(user, user.getUsername(), AuditAction.LOGIN_FAILURE,
                "Invalid credentials (attempt " + attempts + " of " + max + ")", null);
        if (locked) {
            auditService.logForUser(user, user.getUsername(), AuditAction.ACCOUNT_LOCKED,
                    "Account locked for " + properties.getSecurity().getLockoutMinutes()
                            + " minutes after " + max + " failed logins", null);
        }
    }

    public void logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserPrincipal) {
            auditService.log(AuditAction.LOGOUT, "User signed out", null);
        }
        new SecurityContextLogoutHandler().logout(request, response, authentication);
    }

    public AppUser register(RegisterRequest request) {
        if (!settingsService.isRegistrationEnabled()) {
            throw ApiException.forbidden("Self-registration is disabled. Ask an administrator to create your account.");
        }
        String username = request.username().trim();
        if (users.existsByUsernameIgnoreCase(username)) {
            throw ApiException.conflict("Username is already taken.");
        }
        PasswordPolicy.validate(request.password(), username);
        AppUser user = new AppUser();
        user.setUsername(username);
        user.setFullName(blankToNull(request.fullName()));
        user.setEmail(blankToNull(request.email()));
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setRole(Role.ANALYST);
        user.setEnabled(false); // Zero Trust: new accounts need administrator approval
        users.save(user);
        auditService.logForUser(user, username, AuditAction.USER_REGISTERED,
                "Self-registered analyst account (pending administrator approval)", null);
        return user;
    }

    public void changePassword(ChangePasswordRequest request) {
        AppUser user = currentUserService.currentUser();
        if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
            auditService.log(AuditAction.PASSWORD_CHANGED, "Password change rejected: wrong current password", null);
            throw ApiException.badRequest("Current password is incorrect.");
        }
        if (request.currentPassword().equals(request.newPassword())) {
            throw ApiException.badRequest("New password must be different from the current password.");
        }
        PasswordPolicy.validate(request.newPassword(), user.getUsername());
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        users.save(user);
        auditService.log(AuditAction.PASSWORD_CHANGED, "Password changed", null);
    }

    static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
