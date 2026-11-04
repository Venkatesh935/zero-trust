package com.zerotrust.security;

import java.io.IOException;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfException;

import com.zerotrust.entity.AuditAction;
import com.zerotrust.service.AuditService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Returns 403 JSON and records authorization failures in the audit log.
 */
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    private final AuditService auditService;

    public RestAccessDeniedHandler(AuditService auditService) {
        this.auditService = auditService;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException exception) throws IOException {
        if (exception instanceof CsrfException) {
            JsonResponses.write(response, HttpServletResponse.SC_FORBIDDEN,
                    "Invalid or missing CSRF token. Reload the page and try again.");
            return;
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof UserPrincipal) {
            auditService.log(AuditAction.ACCESS_DENIED,
                    request.getMethod() + " " + request.getRequestURI() + " denied (insufficient role)", null);
        }
        JsonResponses.write(response, HttpServletResponse.SC_FORBIDDEN,
                "You do not have permission to perform this action.");
    }
}
