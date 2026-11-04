package com.zerotrust.service;

import static com.zerotrust.service.scanner.ScanFixtures.headers;
import static com.zerotrust.service.scanner.ScanFixtures.response;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import com.zerotrust.entity.ScanRecord;
import com.zerotrust.entity.Severity;
import com.zerotrust.exception.UnsafeTargetException;
import com.zerotrust.security.TargetUrlValidator;
import com.zerotrust.service.scanner.FetchResult;
import com.zerotrust.service.scanner.FindingDraft;
import com.zerotrust.service.scanner.HttpFetcher;
import com.zerotrust.service.scanner.ScanAssessment;
import com.zerotrust.service.scanner.ScanFixtures;
import com.zerotrust.service.scanner.TlsHandshakeFailedException;
import com.zerotrust.service.scanner.TlsInfo;

/**
 * End-to-end scanner logic with mocked HTTP responses and fake DNS.
 * No real network connections are made.
 */
class WebsiteScannerServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-30T00:00:00Z");

    /** Mocked responses keyed by URL; a value of null means "connection refused". */
    private final Map<String, Object> responses = new HashMap<>();
    private final List<String> requested = new ArrayList<>();

    private final TargetUrlValidator validator = new TargetUrlValidator(WebsiteScannerServiceTest::resolve,
            Set.of(80, 443, 8080, 8443));

    private final HttpFetcher fetcher = target -> {
        String url = target.uri().toString();
        requested.add(url);
        Object r = responses.get(url);
        if (r instanceof FetchResult result) {
            return result;
        }
        if (r instanceof IOException e) {
            throw e;
        }
        throw new ConnectException("Connection refused");
    };

    private final WebsiteScannerService scanner = new WebsiteScannerService(validator, fetcher, 5,
            Clock.fixed(NOW, ZoneOffset.UTC));

    static InetAddress[] resolve(String host) throws UnknownHostException {
        return switch (host) {
            case "internal.example.com" -> new InetAddress[] {InetAddress.getByName("10.0.0.7")};
            case "missing.example.com" -> throw new UnknownHostException(host);
            default -> new InetAddress[] {InetAddress.getByName("93.184.216.34")};
        };
    }

    private static Map<String, FindingDraft> byKey(ScanAssessment a) {
        return a.findings().stream().collect(Collectors.toMap(FindingDraft::checkKey, Function.identity(), (x, y) -> x));
    }

    @Test
    void secureSiteWithHttpRedirectScoresWell() {
        TlsInfo tls = ScanFixtures.validTls(NOW, 120);
        responses.put("https://www.example.com/", response("https://www.example.com/", 200, ScanFixtures.secureHeaders(), tls));
        responses.put("http://www.example.com/", response("http://www.example.com/", 301,
                headers("Location", "https://www.example.com/"), null));

        ScanRecord record = new ScanRecord();
        ScanAssessment a = scanner.assess("https://www.example.com", record);

        assertThat(a.reachable()).isTrue();
        assertThat(record.getHttpsAvailable()).isTrue();
        assertThat(record.getHttpRedirectsToHttps()).isTrue();
        assertThat(record.getHttpStatusCode()).isEqualTo(200);
        assertThat(record.getTlsTrusted()).isTrue();
        assertThat(record.getTlsDaysRemaining()).isEqualTo(120);
        assertThat(record.getFinalUrl()).isEqualTo("https://www.example.com/");
        assertThat(a.findings().stream().filter(f -> !f.passed() && f.severity().getDeduction() > 0)).isEmpty();
        assertThat(new RiskScoringService().calculate(a.findings()).score()).isEqualTo(100);
        // the HTTP probe stops at the redirect to HTTPS instead of fetching the HTTPS page twice
        assertThat(requested).containsExactly("https://www.example.com/", "http://www.example.com/");
    }

    @Test
    void followsRedirectsAndRevalidatesEachHop() {
        TlsInfo tls = ScanFixtures.validTls(NOW, 90);
        responses.put("https://example.com/", response("https://example.com/", 301, headers("Location", "https://www.example.com/home"), tls));
        responses.put("https://www.example.com/home", response("https://www.example.com/home", 200,
                headers("Content-Type", "text/html", "Server", "Apache/2.4.41"), ScanFixtures.validTls(NOW, 90)));

        ScanRecord record = new ScanRecord();
        ScanAssessment a = scanner.assess("https://example.com/", record);
        assertThat(record.getRedirectCount()).isEqualTo(1);
        assertThat(record.getFinalUrl()).isEqualTo("https://www.example.com/home");
        assertThat(record.getRedirectChain()).contains("301 https://example.com/ -> https://www.example.com/home");
        Map<String, FindingDraft> r = byKey(a);
        assertThat(r.get("DISCLOSURE_SERVER").severity()).isEqualTo(Severity.LOW);
        assertThat(r.get("HEADER_HSTS").severity()).isEqualTo(Severity.HIGH);
        assertThat(record.getHttpAvailable()).isFalse();
    }

    @Test
    void redirectToInternalAddressIsNotFollowed() {
        responses.put("https://www.example.com/", response("https://www.example.com/", 302,
                headers("Location", "http://internal.example.com/admin"), ScanFixtures.validTls(NOW, 90)));
        responses.put("http://internal.example.com/admin", response("http://internal.example.com/admin", 200, headers(), null));

        ScanAssessment a = scanner.assess("https://www.example.com/", new ScanRecord());
        assertThat(requested).doesNotContain("http://internal.example.com/admin");
        assertThat(byKey(a).get("RESPONSE_REDIRECT_BLOCKED").severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    void redirectToMetadataIpIsNotFollowed() {
        responses.put("https://www.example.com/", response("https://www.example.com/", 302,
                headers("Location", "http://169.254.169.254/latest/meta-data/"), ScanFixtures.validTls(NOW, 90)));
        scanner.assess("https://www.example.com/", new ScanRecord());
        assertThat(requested).noneMatch(u -> u.contains("169.254"));
    }

    @Test
    void redirectLoopIsLimited() {
        TlsInfo tls = ScanFixtures.validTls(NOW, 90);
        responses.put("https://www.example.com/a", response("https://www.example.com/a", 302, headers("Location", "/b"), tls));
        responses.put("https://www.example.com/b", response("https://www.example.com/b", 302, headers("Location", "/a"), tls));
        ScanAssessment a = scanner.assess("https://www.example.com/a", new ScanRecord());
        assertThat(byKey(a).get("RESPONSE_REDIRECTS").severity()).isEqualTo(Severity.MEDIUM);
        assertThat(requested.stream().filter(u -> u.startsWith("https://")).count()).isEqualTo(6); // 1 + 5 redirects
    }

    @Test
    void httpOnlySiteGetsCriticalHttpsFinding() {
        responses.put("http://www.example.com/", response("http://www.example.com/", 200,
                headers("Content-Type", "text/html", "X-Powered-By", "PHP/8.1", "Set-Cookie", "PHPSESSID=abc; path=/"), null));
        ScanRecord record = new ScanRecord();
        ScanAssessment a = scanner.assess("http://www.example.com/", record);
        Map<String, FindingDraft> r = byKey(a);
        assertThat(record.getHttpsAvailable()).isFalse();
        assertThat(r.get("HTTPS_AVAILABLE").severity()).isEqualTo(Severity.CRITICAL);
        assertThat(r.get("HEADER_HSTS").severity()).isEqualTo(Severity.INFORMATIONAL);
        assertThat(r.get("DISCLOSURE_POWERED_BY").severity()).isEqualTo(Severity.LOW);
        assertThat(r.get("COOKIE_PHPSESSID")).isNotNull();
        assertThat(new RiskScoringService().calculate(a.findings()).score()).isLessThanOrEqualTo(49);
    }

    @Test
    void tlsFailureIsReportedWithCertificateDetails() {
        TlsInfo failed = new TlsInfo(null, null, "CN=www.example.com", "CN=Self Signed", List.of(),
                NOW.minusSeconds(86400 * 400L), NOW.minusSeconds(86400 * 2L), false, "PKIX path validation failed");
        responses.put("https://www.example.com/", new TlsHandshakeFailedException(failed, null));
        ScanRecord record = new ScanRecord();
        ScanAssessment a = scanner.assess("https://www.example.com/", record);
        assertThat(a.reachable()).isTrue();
        assertThat(record.getTlsTrusted()).isFalse();
        assertThat(record.getTlsError()).contains("PKIX");
        assertThat(record.getTlsDaysRemaining()).isNegative();
        assertThat(byKey(a).get("TLS_TRUST").severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void unreachableWebsiteFailsTheScan() {
        ScanAssessment a = scanner.assess("https://www.example.com/", new ScanRecord());
        assertThat(a.reachable()).isFalse();
        assertThat(a.errorMessage()).contains("could not be reached");
    }

    @Test
    void registeredInternalUrlIsRejectedBeforeAnyRequest() {
        assertThatThrownBy(() -> scanner.assess("http://internal.example.com/", new ScanRecord()))
                .isInstanceOf(UnsafeTargetException.class);
        assertThat(requested).isEmpty();
    }
}
