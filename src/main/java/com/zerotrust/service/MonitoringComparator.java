package com.zerotrust.service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.springframework.stereotype.Component;

import com.zerotrust.entity.Finding;
import com.zerotrust.entity.FindingCategory;
import com.zerotrust.entity.MonitoringState;
import com.zerotrust.entity.ScanRecord;
import com.zerotrust.entity.ScanStatus;
import com.zerotrust.entity.Severity;
import com.zerotrust.service.scanner.TlsAnalyzer;

/**
 * Compares a monitoring scan with the previous scan of the same website and
 * describes what changed: availability, score, security headers, individual
 * checks and TLS certificate expiry.
 */
@Component
public class MonitoringComparator {

    public record Comparison(MonitoringState state, List<String> changes) {
    }

    public Comparison compare(ScanRecord previous, List<Finding> previousFindings,
            ScanRecord current, List<Finding> currentFindings) {
        List<String> changes = new ArrayList<>();
        boolean currentOk = current.getStatus() == ScanStatus.COMPLETED;

        if (previous == null) {
            changes.add(currentOk
                    ? "Baseline established: security score " + current.getScore() + " (" + current.getRiskLevel().getLabel() + ")."
                    : "Website unavailable: " + current.getErrorMessage());
            addTlsWarnings(current, changes);
            return new Comparison(currentOk ? MonitoringState.BASELINE : MonitoringState.UNAVAILABLE, changes);
        }

        boolean previousOk = previous.getStatus() == ScanStatus.COMPLETED;
        if (!currentOk) {
            changes.add((previousOk ? "Website became unavailable: " : "Website is still unavailable: ")
                    + current.getErrorMessage());
            return new Comparison(MonitoringState.UNAVAILABLE, changes);
        }
        if (!previousOk) {
            changes.add("Website is available again.");
        }

        boolean degraded = false;
        if (previous.getScore() != null && !Objects.equals(previous.getScore(), current.getScore())) {
            int delta = current.getScore() - previous.getScore();
            changes.add("Security score changed from " + previous.getScore() + " to " + current.getScore()
                    + " (" + (delta > 0 ? "+" : "") + delta + ").");
            degraded = delta < 0;
        }

        Map<String, Finding> before = byKey(previousFindings);
        Map<String, Finding> after = byKey(currentFindings);
        for (Finding now : after.values()) {
            Finding then = before.get(now.getCheckKey());
            boolean significant = now.getSeverity().getDeduction() > 0;
            if (then == null) {
                if (!now.isPassed() && significant) {
                    changes.add("New issue: " + now.getTitle() + " [" + now.getSeverity() + "]");
                    degraded |= now.getSeverity().isAtLeast(Severity.HIGH);
                }
            } else if (then.isPassed() && !now.isPassed()) {
                changes.add("Regression: " + now.getTitle() + " [" + now.getSeverity() + "]");
                degraded |= now.getSeverity().isAtLeast(Severity.HIGH);
            } else if (!then.isPassed() && now.isPassed()) {
                changes.add("Resolved: " + then.getTitle());
            } else if (now.getCategory() == FindingCategory.SECURITY_HEADERS
                    && !Objects.equals(normalize(then.getEvidence()), normalize(now.getEvidence()))) {
                changes.add("Header changed: " + now.getTitle() + " (was: " + shorten(then.getEvidence())
                        + "; now: " + shorten(now.getEvidence()) + ")");
            }
        }
        for (Finding then : before.values()) {
            if (!after.containsKey(then.getCheckKey()) && !then.isPassed() && then.getSeverity().getDeduction() > 0) {
                changes.add("No longer reported: " + then.getTitle());
            }
        }

        if (previous.getTlsValidTo() != null && current.getTlsValidTo() != null
                && !previous.getTlsValidTo().equals(current.getTlsValidTo())) {
            changes.add("TLS certificate changed; new expiry " + current.getTlsValidTo() + ".");
        }
        degraded |= addTlsWarnings(current, changes);

        MonitoringState state = degraded ? MonitoringState.DEGRADED
                : changes.isEmpty() ? MonitoringState.STABLE : MonitoringState.CHANGES_DETECTED;
        return new Comparison(state, changes);
    }

    /** Adds certificate expiry/trust warnings; returns true when they are serious. */
    private static boolean addTlsWarnings(ScanRecord scan, List<String> changes) {
        boolean serious = false;
        if (Boolean.FALSE.equals(scan.getTlsTrusted())) {
            changes.add("TLS certificate is not trusted: " + scan.getTlsError());
            serious = true;
        }
        Long days = scan.getTlsDaysRemaining();
        if (days != null && days <= TlsAnalyzer.EXPIRY_MEDIUM_DAYS) {
            changes.add(days < 0 ? "TLS certificate expired " + (-days) + " day(s) ago."
                    : "TLS certificate expires in " + days + " day(s).");
            serious |= days <= TlsAnalyzer.EXPIRY_HIGH_DAYS;
        }
        return serious;
    }

    private static Map<String, Finding> byKey(List<Finding> findings) {
        Map<String, Finding> map = new LinkedHashMap<>();
        if (findings != null) {
            for (Finding f : findings) {
                map.putIfAbsent(f.getCheckKey(), f);
            }
        }
        return map;
    }

    /** CSP nonces change on every response; ignore them when comparing header values. */
    private static String normalize(String evidence) {
        return evidence == null ? null : evidence.replaceAll("'nonce-[^']*'", "'nonce-*'");
    }

    private static String shorten(String text) {
        if (text == null) {
            return "none";
        }
        return text.length() > 80 ? text.substring(0, 77) + "..." : text;
    }
}
