package com.zerotrust.security;

import java.io.IOException;
import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.zerotrust.entity.AppUser;
import com.zerotrust.entity.AuditAction;
import com.zerotrust.repository.AppUserRepository;
import com.zerotrust.service.AuditService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * "Never trust, always verify": on every request with an authenticated
 * session, the user is re-checked against the database. If the account was
 * deleted, disabled or its role changed since login, the session is revoked
 * immediately instead of remaining valid until it expires.
 */
public class SessionRevalidationFilter extends OncePerRequestFilter {

    private final AppUserRepository users;
    private final AuditService auditService;

    public SessionRevalidationFilter(AppUserRepository users, AuditService auditService) {
        this.users = users;
        this.auditService = auditService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return path.startsWith("/css/") || path.startsWith("/js/") || path.startsWith("/img/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof UserPrincipal principal) {
            String reason = revocationReason(principal);
            if (reason != null) {
                auditService.logForUser(null, principal.getUsername(), AuditAction.SESSION_REVOKED,
                        "Session revoked: " + reason, null);
                HttpSession session = request.getSession(false);
                if (session != null) {
                    session.invalidate();
                }
                SecurityContextHolder.clearContext();
                if (JsonResponses.isApiRequest(request)) {
                    JsonResponses.write(response, HttpServletResponse.SC_UNAUTHORIZED,
                            "Your session is no longer valid (" + reason + "). Please sign in again.");
                } else {
                    response.sendRedirect(request.getContextPath() + "/login.html");
                }
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private String revocationReason(UserPrincipal principal) {
        Optional<AppUser> user = users.findById(principal.getId());
        if (user.isEmpty()) {
            return "account deleted";
        }
        if (!user.get().isEnabled()) {
            return "account disabled";
        }
        if (user.get().getRole() != principal.getRole()) {
            return "role changed";
        }
        return null;
    }
}
