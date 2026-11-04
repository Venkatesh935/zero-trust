package com.zerotrust.service.scanner;

import java.util.List;

/**
 * Outcome of a passive assessment: the check results, or the reason the
 * website could not be assessed at all.
 */
public record ScanAssessment(List<FindingDraft> findings, boolean reachable, String errorMessage) {

    public static ScanAssessment unreachable(String errorMessage) {
        return new ScanAssessment(List.of(), false, errorMessage);
    }
}
