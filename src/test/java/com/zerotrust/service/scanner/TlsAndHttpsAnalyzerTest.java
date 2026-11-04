package com.zerotrust.service.scanner;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import com.zerotrust.entity.Severity;
import com.zerotrust.service.scanner.HttpsAnalyzer.HttpsFacts;

/**
 * TLS certificate and HTTPS assessment logic.
 */
class TlsAndHttpsAnalyzerTest {

    private static final Instant NOW = Instant.parse("2026-10-30T00:00:00Z");
    private final TlsAnalyzer tls = new TlsAnalyzer();
    private final HttpsAnalyzer https = new HttpsAnalyzer();

    private static Map<String, FindingDraft> byKey(List<FindingDraft> list) {
        return list.stream().collect(Collectors.toMap(FindingDraft::checkKey, Function.identity()));
    }

    @Test
    void validCertificateWithLongValidityPasses() {
        Map<String, FindingDraft> r = byKey(tls.analyze(ScanFixtures.validTls(NOW, 200), NOW));
        assertThat(r.get("TLS_TRUST").passed()).isTrue();
        assertThat(r.get("TLS_EXPIRY").passed()).isTrue();
        assertThat(r.get("TLS_PROTOCOL").passed()).isTrue();
        assertThat(TlsAnalyzer.daysRemaining(ScanFixtures.validTls(NOW, 200), NOW)).isEqualTo(200);
    }

    @Test
    void certificateExpiringSoonIsFlaggedByThreshold() {
        assertThat(byKey(tls.analyze(ScanFixtures.validTls(NOW, 25), NOW)).get("TLS_EXPIRY").severity())
                .isEqualTo(Severity.MEDIUM);
        assertThat(byKey(tls.analyze(ScanFixtures.validTls(NOW, 7), NOW)).get("TLS_EXPIRY").severity())
                .isEqualTo(Severity.HIGH);
    }

    @Test
    void expiredAndUntrustedCertificateIsCritical() {
        TlsInfo expired = new TlsInfo(null, null, "CN=old.example.com", "CN=CA", List.of(),
                NOW.minus(Duration.ofDays(400)), NOW.minus(Duration.ofDays(3)), false,
                "PKIX path validation failed: validity check failed");
        Map<String, FindingDraft> r = byKey(tls.analyze(expired, NOW));
        assertThat(r.get("TLS_TRUST").severity()).isEqualTo(Severity.CRITICAL);
        assertThat(r.get("TLS_TRUST").evidence()).contains("validity check failed");
        assertThat(r.get("TLS_EXPIRY").severity()).isEqualTo(Severity.CRITICAL);
        assertThat(r).doesNotContainKey("TLS_PROTOCOL");
    }

    @Test
    void handshakeFailureWithoutCertificateIsHandledSafely() {
        TlsInfo failed = TlsInfo.failed(null, "Received fatal alert: handshake_failure");
        Map<String, FindingDraft> r = byKey(tls.analyze(failed, NOW));
        assertThat(r.get("TLS_TRUST").passed()).isFalse();
        assertThat(r).doesNotContainKey("TLS_EXPIRY");
    }

    @Test
    void outdatedProtocolIsHigh() {
        TlsInfo old = new TlsInfo("TLSv1.1", "X", "CN=a", "CN=b", List.of(), NOW.minus(Duration.ofDays(1)),
                NOW.plus(Duration.ofDays(100)), true, null);
        assertThat(byKey(tls.analyze(old, NOW)).get("TLS_PROTOCOL").severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void noTlsWhenHttpsUnavailable() {
        assertThat(tls.analyze(null, NOW)).singleElement().matches(f -> f.checkKey().equals("TLS_NOT_ASSESSED"));
    }

    @Test
    void httpsAvailableWithRedirectPasses() {
        Map<String, FindingDraft> r = byKey(https.analyze(new HttpsFacts(true, true, false, true, true, false)));
        assertThat(r.get("HTTPS_AVAILABLE").passed()).isTrue();
        assertThat(r.get("HTTP_REDIRECT").passed()).isTrue();
        assertThat(r).doesNotContainKey("HTTPS_DOWNGRADE");
    }

    @Test
    void httpsUnavailableIsCritical() {
        Map<String, FindingDraft> r = byKey(https.analyze(new HttpsFacts(false, false, false, true, false, false)));
        assertThat(r.get("HTTPS_AVAILABLE").severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void missingRedirectAndDowngradeAreFlagged() {
        Map<String, FindingDraft> r = byKey(https.analyze(new HttpsFacts(true, true, false, true, false, true)));
        assertThat(r.get("HTTP_REDIRECT").severity()).isEqualTo(Severity.MEDIUM);
        assertThat(r.get("HTTPS_DOWNGRADE").severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void untrustedCertificateMeansHttpsNotSecure() {
        Map<String, FindingDraft> r = byKey(https.analyze(new HttpsFacts(true, false, true, false, null, false)));
        assertThat(r.get("HTTPS_AVAILABLE").severity()).isEqualTo(Severity.HIGH);
        assertThat(r.get("HTTP_REDIRECT").passed()).isTrue(); // plain HTTP not served at all
    }
}
