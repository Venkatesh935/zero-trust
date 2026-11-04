package com.zerotrust.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;

import com.zerotrust.entity.FindingCategory;
import com.zerotrust.entity.RiskLevel;
import com.zerotrust.entity.ScorableFinding;
import com.zerotrust.entity.Severity;

/**
 * Transparent, deterministic risk scoring.
 *
 * <ol>
 *   <li>Start from 100 points.</li>
 *   <li>Each failed check deducts points by severity:
 *       CRITICAL 25, HIGH 15, MEDIUM 8, LOW 3, INFORMATIONAL 0.</li>
 *   <li>Deductions are capped per category (HTTPS 35, TLS 30, Headers 35,
 *       Cookies 15, HTTP response 10, Disclosure 6) so many small issues in
 *       one area cannot outweigh everything else.</li>
 *   <li>If any CRITICAL finding exists, the score is limited to at most 49,
 *       so a site with a critical weakness can never be rated Good or Excellent.</li>
 * </ol>
 *
 * The score measures security configuration hygiene observed by passive checks.
 * It is not proof that a website is secure or vulnerable.
 */
@Service
public class RiskScoringService {

    public static final int MAX_SCORE = 100;
    public static final int CRITICAL_CEILING = 49;

    public static final String DISCLAIMER = "This score reflects the security configuration observed by passive "
            + "checks (HTTPS, TLS, headers, cookies, response metadata). It is not a penetration test and is not "
            + "proof that a website is completely secure or vulnerable.";

    public record CategoryScore(FindingCategory category, String label, int failedChecks,
            int rawDeduction, int maxDeduction, int appliedDeduction) {
    }

    public record RiskResult(int score, RiskLevel riskLevel, List<CategoryScore> categories,
            boolean criticalCeilingApplied, int totalFindings, Map<Severity, Integer> severityCounts) {

        public int count(Severity severity) {
            return severityCounts.getOrDefault(severity, 0);
        }
    }

    public RiskResult calculate(Collection<? extends ScorableFinding> findings) {
        Map<FindingCategory, Integer> raw = new EnumMap<>(FindingCategory.class);
        Map<FindingCategory, Integer> failed = new EnumMap<>(FindingCategory.class);
        Map<Severity, Integer> severityCounts = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            severityCounts.put(s, 0);
        }

        int total = 0;
        for (ScorableFinding finding : findings) {
            if (finding.isPassed()) {
                continue;
            }
            total++;
            severityCounts.merge(finding.getSeverity(), 1, Integer::sum);
            failed.merge(finding.getCategory(), 1, Integer::sum);
            raw.merge(finding.getCategory(), finding.getSeverity().getDeduction(), Integer::sum);
        }

        List<CategoryScore> categories = new ArrayList<>();
        int totalDeduction = 0;
        for (FindingCategory category : FindingCategory.values()) {
            int rawDeduction = raw.getOrDefault(category, 0);
            int applied = Math.min(rawDeduction, category.getMaxDeduction());
            totalDeduction += applied;
            if (category != FindingCategory.AVAILABILITY) {
                categories.add(new CategoryScore(category, category.getLabel(), failed.getOrDefault(category, 0),
                        rawDeduction, category.getMaxDeduction(), applied));
            }
        }

        int score = Math.max(0, MAX_SCORE - totalDeduction);
        boolean ceiling = false;
        if (severityCounts.get(Severity.CRITICAL) > 0 && score > CRITICAL_CEILING) {
            score = CRITICAL_CEILING;
            ceiling = true;
        }
        return new RiskResult(score, RiskLevel.fromScore(score), categories, ceiling, total, severityCounts);
    }

    public static String describe(RiskLevel level) {
        return switch (level) {
            case EXCELLENT -> "Strong security configuration with few or no weaknesses detected.";
            case GOOD -> "Generally well configured; minor improvements recommended.";
            case MODERATE -> "Several configuration weaknesses; improvements should be planned.";
            case HIGH_RISK -> "Significant weaknesses that should be fixed promptly.";
            case CRITICAL_RISK -> "Severe weaknesses requiring immediate attention.";
        };
    }
}
