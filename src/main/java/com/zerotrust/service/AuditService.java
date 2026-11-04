package com.zerotrust.service;

import java.time.Instant;
import java.util.regex.Pattern;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.zerotrust.dto.AuditLogDto;
import com.zerotrust.dto.PageResponse;
import com.zerotrust.entity.AppUser;
import com.zerotrust.entity.AuditAction;
import com.zerotrust.entity.AuditLog;
import com.zerotrust.repository.AppUserRepository;
import com.zerotrust.repository.AuditLogRepository;
import com.zerotrust.repository.MongoQueries;
import com.zerotrust.security.UserPrincipal;

/**
 * Writes and queries the audit trail. Each entry is saved immediately as its
 * own document, so it is kept even if the surrounding operation fails.
 * Descriptions are sanitized; callers must never pass passwords, tokens or cookie values.
 */
@Service
public class AuditService {

    public static final String SYSTEM_USER = "system";

    private final AuditLogRepository repository;
    private final AppUserRepository users;
    private final MongoOperations mongo;

    public AuditService(AuditLogRepository repository, AppUserRepository users, MongoOperations mongo) {
        this.repository = repository;
        this.users = users;
        this.mongo = mongo;
    }

    /** Records an action performed by the currently authenticated user (or the system). */
    public void log(AuditAction action, String description, Long targetId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof UserPrincipal principal) {
            save(users.findById(principal.getId()).orElse(null), principal.getUsername(), action, description,
                    targetId);
        } else {
            save(null, SYSTEM_USER, action, description, targetId);
        }
    }

    /** Records an action for an explicit user, e.g. a failed login where nobody is authenticated. */
    public void logForUser(AppUser user, String username, AuditAction action, String description, Long targetId) {
        AppUser ref = user != null && user.getId() != null ? user : null;
        save(ref, username, action, description, targetId);
    }

    private void save(AppUser user, String username, AuditAction action, String description, Long targetId) {
        AuditLog entry = new AuditLog();
        entry.setUser(user);
        entry.setUsername(sanitize(username, 50));
        entry.setAction(action);
        entry.setDescription(sanitize(description, 1000));
        entry.setTargetId(targetId);
        entry.setIpAddress(clientIp());
        repository.save(entry);
    }

    public PageResponse<AuditLogDto> search(AuditAction action, String username, Instant from, Instant to,
            int page, int size) {
        Query query = new Query();
        if (action != null) {
            query.addCriteria(Criteria.where("action").is(action));
        }
        if (username != null && !username.isBlank()) {
            query.addCriteria(Criteria.where("username").regex(Pattern.quote(username.trim()), "i"));
        }
        if (from != null || to != null) {
            Criteria created = Criteria.where("createdAt");
            if (from != null) {
                created = created.gte(from);
            }
            if (to != null) {
                created = created.lt(to);
            }
            query.addCriteria(created);
        }
        PageRequest pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt", "id"));
        return PageResponse.of(MongoQueries.page(mongo, query, pageable, AuditLog.class), AuditLogDto::from);
    }

    /** Removes control characters (prevents log injection) and limits length. */
    public static String sanitize(String text, int max) {
        if (text == null) {
            return null;
        }
        String clean = text.replaceAll("[\\p{Cntrl}]", " ").strip();
        return clean.length() > max ? clean.substring(0, max) : clean;
    }

    /** Like {@link #sanitize} but keeps line breaks, for multi-line change lists. */
    public static String sanitizeLines(String text, int max) {
        if (text == null) {
            return null;
        }
        String clean = text.replaceAll("[\\p{Cntrl}&&[^\\n]]", " ").strip();
        return clean.length() > max ? clean.substring(0, max) : clean;
    }

    private static String clientIp() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (attrs instanceof ServletRequestAttributes servletAttrs) {
            // X-Forwarded-For is deliberately ignored: it is client-controlled.
            return servletAttrs.getRequest().getRemoteAddr();
        }
        return null;
    }
}
