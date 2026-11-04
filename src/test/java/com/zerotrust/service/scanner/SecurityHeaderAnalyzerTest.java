package com.zerotrust.service.scanner;

import static com.zerotrust.service.scanner.ScanFixtures.headers;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import com.zerotrust.entity.Severity;

class SecurityHeaderAnalyzerTest {

    private final SecurityHeaderAnalyzer analyzer = new SecurityHeaderAnalyzer();

    private Map<String, FindingDraft> analyze(ResponseHeaders h, boolean https) {
        List<FindingDraft> results = analyzer.analyze(h, https);
        assertThat(results).hasSize(6);
        return results.stream().collect(Collectors.toMap(FindingDraft::checkKey, Function.identity()));
    }

    @Test
    void allHeadersPresentAndStrongPass() {
        Map<String, FindingDraft> r = analyze(ScanFixtures.secureHeaders(), true);
        assertThat(r.values()).allMatch(FindingDraft::passed);
        assertThat(r.get("HEADER_HSTS").evidence()).contains("max-age=31536000");
    }

    @Test
    void missingHeadersAreReportedWithSeverityAndRecommendation() {
        Map<String, FindingDraft> r = analyze(headers("Content-Type", "text/html"), true);
        assertThat(r.values()).noneMatch(FindingDraft::passed);
        assertThat(r.get("HEADER_HSTS").severity()).isEqualTo(Severity.HIGH);
        assertThat(r.get("HEADER_CSP").severity()).isEqualTo(Severity.MEDIUM);
        assertThat(r.get("HEADER_XFO").severity()).isEqualTo(Severity.MEDIUM);
        assertThat(r.get("HEADER_XCTO").severity()).isEqualTo(Severity.LOW);
        assertThat(r.get("HEADER_REFERRER").severity()).isEqualTo(Severity.LOW);
        assertThat(r.get("HEADER_PERMISSIONS").severity()).isEqualTo(Severity.LOW);
        assertThat(r.values()).allMatch(f -> f.recommendation() != null && f.evidence().equals("Not present"));
    }

    @Test
    void headerNamesAreCaseInsensitive() {
        Map<String, FindingDraft> r = analyze(headers("x-content-type-options", "NOSNIFF", "x-frame-options", "sameorigin"), true);
        assertThat(r.get("HEADER_XCTO").passed()).isTrue();
        assertThat(r.get("HEADER_XFO").passed()).isTrue();
    }

    @Test
    void weakHstsConfigurationsAreFlagged() {
        assertThat(analyzer.checkHsts("max-age=0", true).severity()).isEqualTo(Severity.MEDIUM);
        assertThat(analyzer.checkHsts("max-age=3600", true).severity()).isEqualTo(Severity.LOW);
        assertThat(analyzer.checkHsts("includeSubDomains", true).severity()).isEqualTo(Severity.MEDIUM);
        assertThat(analyzer.checkHsts("max-age=15552000", true).passed()).isTrue();
    }

    @Test
    void hstsIsNotApplicableOverPlainHttp() {
        FindingDraft f = analyzer.checkHsts(null, false);
        assertThat(f.passed()).isFalse();
        assertThat(f.severity()).isEqualTo(Severity.INFORMATIONAL);
    }

    @Test
    void weakCspIsFlagged() {
        assertThat(analyzer.checkCsp("default-src * 'unsafe-inline'", null).severity()).isEqualTo(Severity.MEDIUM);
        assertThat(analyzer.checkCsp("script-src 'self' 'unsafe-eval'", null).severity()).isEqualTo(Severity.LOW);
        assertThat(analyzer.checkCsp("img-src 'self'", null).severity()).isEqualTo(Severity.LOW);
        // unsafe-inline is ignored by browsers when a nonce is present
        assertThat(analyzer.checkCsp("script-src 'self' 'nonce-abc' 'unsafe-inline'", null).passed()).isTrue();
    }

    @Test
    void reportOnlyCspIsNotEnforced() {
        FindingDraft f = analyzer.checkCsp(null, "default-src 'self'");
        assertThat(f.passed()).isFalse();
        assertThat(f.title()).contains("report-only");
    }

    @Test
    void frameAncestorsSatisfiesClickjackingCheck() {
        assertThat(analyzer.checkFrameOptions(null, "default-src 'self'; frame-ancestors 'self'").passed()).isTrue();
        assertThat(analyzer.checkFrameOptions("ALLOW-FROM https://a.example", null).severity()).isEqualTo(Severity.LOW);
        assertThat(analyzer.checkFrameOptions("bogus", null).passed()).isFalse();
    }

    @Test
    void unsafeReferrerPoliciesAreFlagged() {
        assertThat(analyzer.checkReferrerPolicy("unsafe-url").passed()).isFalse();
        assertThat(analyzer.checkReferrerPolicy("no-referrer-when-downgrade").passed()).isFalse();
        // the last valid value in a comma-separated list is used
        assertThat(analyzer.checkReferrerPolicy("unsafe-url, strict-origin-when-cross-origin").passed()).isTrue();
    }

    @Test
    void cspDirectiveParsing() {
        assertThat(SecurityHeaderAnalyzer.directive("default-src 'self'; Frame-Ancestors 'none'", "frame-ancestors"))
                .isEqualTo("'none'");
        assertThat(SecurityHeaderAnalyzer.directive("default-src 'self'", "script-src")).isNull();
    }
}
