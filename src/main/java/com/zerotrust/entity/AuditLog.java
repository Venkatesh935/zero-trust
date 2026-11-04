package com.zerotrust.entity;

import java.time.Instant;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.DocumentReference;

/**
 * Immutable record of a security-relevant action. Passwords, session
 * identifiers and cookie values are never written to the audit log.
 */
@Document("audit_logs")
public class AuditLog extends LongIdEntity {

    /**
     * Acting user. Only a reference by ID: audit entries are saved immediately
     * as separate documents (so they survive failures), and the history must
     * remain intact after a user is deleted.
     */
    @DocumentReference
    private AppUser user;

    /** Username snapshot, kept even if the user is later deleted or never existed. */
    private String username;

    @Indexed
    private AuditAction action;

    private String description;

    /** Related website target ID; intentionally not a foreign key so history survives deletion. */
    private Long targetId;

    private String ipAddress;

    @Indexed
    private Instant createdAt = Instant.now();

    public AppUser getUser() {
        return user;
    }

    public void setUser(AppUser user) {
        this.user = user;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public AuditAction getAction() {
        return action;
    }

    public void setAction(AuditAction action) {
        this.action = action;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Long getTargetId() {
        return targetId;
    }

    public void setTargetId(Long targetId) {
        this.targetId = targetId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
