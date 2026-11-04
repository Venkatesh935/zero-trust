package com.zerotrust.dto;

import java.time.Instant;
import java.util.List;

import com.zerotrust.entity.FindingCategory;
import com.zerotrust.entity.RiskLevel;
import com.zerotrust.entity.ScanRecord;
import com.zerotrust.service.RiskScoringService;
import com.zerotrust.service.RiskScoringService.RiskResult;

/**
 * Complete result of one scan: metadata, risk assessment and all check results.
 */
public record ScanResponse(
        ScanSummaryDto summary,
        String scannedUrl,
        String errorMessage,
        Https https,
        Response response,
        Tls tls,
        RiskAssessment risk,
        List<FindingDto> findings) {

    public record Https(Boolean httpsAvailable, Boolean httpAvailable, Boolean httpRedirectsToHttps) {
    }

    public record Response(Integer statusCode, Long responseTimeMs, String finalUrl, String contentType,
            Integer redirectCount, List<String> redirectChain) {
    }

    public record Tls(String protocol, String cipherSuite, String subject, String issuer, Instant validFrom,
            Instant validTo, Long daysRemaining, Boolean trusted, String error) {
    }

    public record CategoryScore(FindingCategory category, String label, int failedChecks, int rawDeduction,
            int maxDeduction, int appliedDeduction) {
    }

    public record RiskAssessment(Integer score, RiskLevel riskLevel, String riskLabel, String riskDescription,
            int totalFindings, int critical, int high, int medium, int low, int informational,
            boolean criticalCeilingApplied, List<CategoryScore> categories, List<FindingDto> mainWeaknesses,
            List<String> recommendations, String disclaimer) {
    }

    public static ScanResponse from(ScanRecord s, List<FindingDto> findings, RiskResult risk) {
        List<String> chain = s.getRedirectChain() == null ? List.of() : List.of(s.getRedirectChain().split("\n"));

        RiskAssessment assessment = null;
        if (risk != null && s.getScore() != null) {
            List<FindingDto> failed = findings.stream().filter(f -> !f.passed())
                    .sorted((a, b) -> Integer.compare(a.severity().ordinal(), b.severity().ordinal()))
                    .toList();
            List<FindingDto> weaknesses = failed.stream()
                    .filter(f -> f.severity().getDeduction() > 0).limit(5).toList();
            List<String> recommendations = failed.stream()
                    .filter(f -> f.recommendation() != null && f.severity().getDeduction() > 0)
                    .map(f -> "[" + f.severity() + "] " + f.recommendation())
                    .distinct().limit(10).toList();
            assessment = new RiskAssessment(s.getScore(), s.getRiskLevel(), s.getRiskLevel().getLabel(),
                    RiskScoringService.describe(s.getRiskLevel()), risk.totalFindings(),
                    s.getCriticalCount(), s.getHighCount(), s.getMediumCount(), s.getLowCount(), s.getInfoCount(),
                    risk.criticalCeilingApplied(),
                    risk.categories().stream().map(c -> new CategoryScore(c.category(), c.label(), c.failedChecks(),
                            c.rawDeduction(), c.maxDeduction(), c.appliedDeduction())).toList(),
                    weaknesses, recommendations, RiskScoringService.DISCLAIMER);
        }

        return new ScanResponse(ScanSummaryDto.from(s), s.getScannedUrl(), s.getErrorMessage(),
                new Https(s.getHttpsAvailable(), s.getHttpAvailable(), s.getHttpRedirectsToHttps()),
                new Response(s.getHttpStatusCode(), s.getResponseTimeMs(), s.getFinalUrl(), s.getContentType(),
                        s.getRedirectCount(), chain),
                new Tls(s.getTlsProtocol(), s.getTlsCipherSuite(), s.getTlsSubject(), s.getTlsIssuer(),
                        s.getTlsValidFrom(), s.getTlsValidTo(), s.getTlsDaysRemaining(), s.getTlsTrusted(),
                        s.getTlsError()),
                assessment, findings);
    }
}
