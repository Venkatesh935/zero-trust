package com.zerotrust.dto;

import java.time.Instant;
import java.util.List;

import com.zerotrust.dto.AuthDtos.UserRef;
import com.zerotrust.entity.RiskLevel;
import com.zerotrust.entity.ScanStatus;
import com.zerotrust.entity.WebsiteTarget;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public final class WebsiteDtos {

    private WebsiteDtos() {
    }

    public record WebsiteRequest(
            @NotBlank(message = "Website name is required.") @Size(max = 100, message = "Name must be at most 100 characters.") String name,
            @NotBlank(message = "Website URL is required.") @Size(max = 500, message = "URL must be at most 500 characters.") String url,
            @Size(max = 1000, message = "Description must be at most 1000 characters.") String description,
            @AssertTrue(message = "You must confirm that you own or are authorized to assess this website.") boolean authorizationConfirmed,
            @Size(max = 500, message = "Authorization note must be at most 500 characters.") String authorizationNote,
            List<Long> analystIds) {
    }

    public record WebsiteDto(Long id, String name, String url, String hostname, String description,
            boolean authorizationConfirmed, String authorizationNote, UserRef createdBy, List<UserRef> analysts,
            Long lastScanId, Integer lastScore, RiskLevel lastRiskLevel, String lastRiskLabel,
            ScanStatus lastScanStatus, Instant lastScanAt, boolean monitoringEnabled,
            Instant createdAt, Instant updatedAt) {

        public static WebsiteDto from(WebsiteTarget t, boolean monitoringEnabled) {
            return new WebsiteDto(t.getId(), t.getName(), t.getUrl(), t.getHostname(), t.getDescription(),
                    t.isAuthorizationConfirmed(), t.getAuthorizationNote(), UserRef.from(t.getCreatedBy()),
                    t.getAssignedAnalysts().stream().map(UserRef::from).toList(),
                    t.getLastScanId(), t.getLastScore(), t.getLastRiskLevel(),
                    t.getLastRiskLevel() == null ? null : t.getLastRiskLevel().getLabel(),
                    t.getLastScanStatus(), t.getLastScanAt(), monitoringEnabled, t.getCreatedAt(), t.getUpdatedAt());
        }
    }
}
