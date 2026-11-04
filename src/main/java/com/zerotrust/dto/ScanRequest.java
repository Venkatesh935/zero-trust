package com.zerotrust.dto;

import jakarta.validation.constraints.NotNull;

/**
 * Starts a scan of a registered website. Only the target ID is accepted:
 * arbitrary URLs can never be scanned.
 */
public record ScanRequest(@NotNull(message = "websiteId is required.") Long websiteId) {
}
