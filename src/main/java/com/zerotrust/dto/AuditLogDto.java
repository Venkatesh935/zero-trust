package com.zerotrust.dto;

import java.time.Instant;

import com.zerotrust.entity.AuditAction;
import com.zerotrust.entity.AuditLog;

public record AuditLogDto(Long id, String username, AuditAction action, String description, Long targetId,
        String ipAddress, Instant timestamp) {

    public static AuditLogDto from(AuditLog a) {
        return new AuditLogDto(a.getId(), a.getUsername(), a.getAction(), a.getDescription(), a.getTargetId(),
                a.getIpAddress(), a.getCreatedAt());
    }
}
