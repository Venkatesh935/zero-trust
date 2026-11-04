package com.zerotrust.dto;

import java.util.Set;

public record SettingsDto(
        boolean registrationEnabled,
        int connectTimeoutMs,
        int readTimeoutMs,
        int maxRedirects,
        int maxHeaderBytes,
        Set<Integer> allowedPorts,
        int manualScanCooldownSeconds,
        int monitoringMinIntervalMinutes,
        int monitoringMaxIntervalMinutes,
        int maxFailedLogins,
        int lockoutMinutes) {

    public record SettingsUpdateRequest(Boolean registrationEnabled) {
    }
}
