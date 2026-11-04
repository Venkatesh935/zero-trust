package com.zerotrust.dto;

import java.time.Instant;

import com.zerotrust.entity.Finding;
import com.zerotrust.entity.FindingCategory;
import com.zerotrust.entity.Severity;

public record FindingDto(Long id, Long scanId, Long websiteId, String websiteName, FindingCategory category,
        String categoryLabel, String checkKey, String title, String description, Severity severity, boolean passed,
        String evidence, String recommendation, Instant scanDate) {

    public static FindingDto from(Finding f) {
        return new FindingDto(f.getId(), f.getScan().getId(), f.getScan().getTarget().getId(),
                f.getScan().getTarget().getName(), f.getCategory(), f.getCategory().getLabel(), f.getCheckKey(),
                f.getTitle(), f.getDescription(), f.getSeverity(), f.isPassed(), f.getEvidence(),
                f.getRecommendation(), f.getScan().getStartedAt());
    }
}
