package com.zerotrust.service.scanner;

import com.zerotrust.entity.FindingCategory;
import com.zerotrust.entity.ScorableFinding;
import com.zerotrust.entity.Severity;

/**
 * Result of one security check before it is persisted.
 */
public record FindingDraft(
        FindingCategory category,
        String checkKey,
        String title,
        String description,
        Severity severity,
        boolean passed,
        String evidence,
        String recommendation) implements ScorableFinding {

    private static final int MAX_TEXT = 1000;

    public FindingDraft {
        title = truncate(title, 200);
        description = truncate(description, MAX_TEXT);
        evidence = truncate(evidence, MAX_TEXT);
        recommendation = truncate(recommendation, MAX_TEXT);
    }

    public static FindingDraft pass(FindingCategory category, String checkKey, String title,
            String description, String evidence) {
        return new FindingDraft(category, checkKey, title, description, Severity.INFORMATIONAL, true, evidence, null);
    }

    public static FindingDraft fail(FindingCategory category, String checkKey, Severity severity, String title,
            String description, String evidence, String recommendation) {
        return new FindingDraft(category, checkKey, title, description, severity, false, evidence, recommendation);
    }

    static String truncate(String text, int max) {
        if (text == null || text.length() <= max) {
            return text;
        }
        return text.substring(0, max - 3) + "...";
    }

    @Override
    public FindingCategory getCategory() {
        return category;
    }

    @Override
    public Severity getSeverity() {
        return severity;
    }

    @Override
    public boolean isPassed() {
        return passed;
    }

    @Override
    public String getCheckKey() {
        return checkKey;
    }

    @Override
    public String getTitle() {
        return title;
    }
}
