package com.zerotrust.service;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.zerotrust.config.ZeroTrustProperties;
import com.zerotrust.entity.FindingCategory;
import com.zerotrust.entity.ScanRecord;
import com.zerotrust.entity.Severity;
import com.zerotrust.exception.UnsafeTargetException;
import com.zerotrust.security.TargetUrlValidator;
import com.zerotrust.security.TargetUrlValidator.ValidatedUrl;
import com.zerotrust.service.scanner.CookieAnalyzer;
import com.zerotrust.service.scanner.DisclosureAnalyzer;
import com.zerotrust.service.scanner.FetchResult;
import com.zerotrust.service.scanner.FindingDraft;
import com.zerotrust.service.scanner.HttpFetcher;
import com.zerotrust.service.scanner.HttpsAnalyzer;
import com.zerotrust.service.scanner.HttpsAnalyzer.HttpsFacts;
import com.zerotrust.service.scanner.ResponseAnalyzer;
import com.zerotrust.service.scanner.ResponseAnalyzer.ChainFacts;
import com.zerotrust.service.scanner.ScanAssessment;
import com.zerotrust.service.scanner.SecurityHeaderAnalyzer;
import com.zerotrust.service.scanner.TlsAnalyzer;
import com.zerotrust.service.scanner.TlsHandshakeFailedException;
import com.zerotrust.service.scanner.TlsInfo;

/**
 * Passive website security assessment engine.
 *
 * <p>For a registered URL it requests the HTTPS and HTTP versions of the page,
 * follows redirects manually (validating every destination against the SSRF
 * rules), and runs the HTTPS, TLS, header, cookie, response and disclosure
 * checks on the collected status lines and headers. No attack payloads are
 * sent and no page content is stored.</p>
 */
@Service
public class WebsiteScannerService {

    private final TargetUrlValidator validator;
    private final HttpFetcher fetcher;
    private final int maxRedirects;
    private final Clock clock;

    private final HttpsAnalyzer httpsAnalyzer = new HttpsAnalyzer();
    private final TlsAnalyzer tlsAnalyzer = new TlsAnalyzer();
    private final SecurityHeaderAnalyzer headerAnalyzer = new SecurityHeaderAnalyzer();
    private final CookieAnalyzer cookieAnalyzer = new CookieAnalyzer();
    private final DisclosureAnalyzer disclosureAnalyzer = new DisclosureAnalyzer();
    private final ResponseAnalyzer responseAnalyzer = new ResponseAnalyzer();

    @Autowired
    public WebsiteScannerService(TargetUrlValidator validator, HttpFetcher fetcher, ZeroTrustProperties properties) {
        this(validator, fetcher, properties.getScanner().getMaxRedirects(), Clock.systemUTC());
    }

    public WebsiteScannerService(TargetUrlValidator validator, HttpFetcher fetcher, int maxRedirects, Clock clock) {
        this.validator = validator;
        this.fetcher = fetcher;
        this.maxRedirects = maxRedirects;
        this.clock = clock;
    }

    /** Result of following a redirect chain from one starting URL. */
    record Chain(List<FetchResult> hops, TlsInfo tlsFailure, String error, String blockedRedirect,
            boolean tooManyRedirects) {

        FetchResult last() {
            return hops.get(hops.size() - 1);
        }

        long totalTimeMs() {
            return hops.stream().mapToLong(FetchResult::responseTimeMs).sum();
        }
    }

    /**
     * Assesses the registered URL and fills the response/TLS metadata of {@code sink}.
     *
     * @throws UnsafeTargetException if the registered URL itself fails SSRF validation
     */
    public ScanAssessment assess(String registeredUrl, ScanRecord sink) {
        ValidatedUrl registered = validator.validate(registeredUrl);
        Instant now = clock.instant();

        URI httpsUri = withScheme(registered, "https");
        URI httpUri = withScheme(registered, "http");

        Chain https = follow(httpsUri, false);
        boolean httpsAvailable = !https.hops().isEmpty();
        // When HTTPS works, stop the HTTP chain at its redirect to HTTPS to avoid duplicate requests.
        Chain http = follow(httpUri, httpsAvailable);
        boolean httpAvailable = !http.hops().isEmpty();

        TlsInfo tls = httpsAvailable ? https.hops().get(0).tls() : https.tlsFailure();
        Boolean redirectsToHttps = httpAvailable ? redirectsToHttps(http.hops().get(0)) : null;

        sink.setHttpsAvailable(httpsAvailable);
        sink.setHttpAvailable(httpAvailable);
        sink.setHttpRedirectsToHttps(redirectsToHttps);
        applyTls(sink, tls, now);

        if (!httpsAvailable && !httpAvailable && tls == null) {
            String reason = https.error() != null ? https.error() : http.error();
            return ScanAssessment.unreachable("Website could not be reached over HTTPS or HTTP"
                    + (reason != null ? ": " + reason : "."));
        }

        boolean downgrade = httpsAvailable && https.hops().stream()
                .anyMatch(hop -> "http".equals(hop.url().getScheme()));

        List<FindingDraft> findings = new ArrayList<>();
        findings.addAll(httpsAnalyzer.analyze(new HttpsFacts(registered.https(), httpsAvailable,
                https.tlsFailure() != null, httpAvailable, redirectsToHttps, downgrade)));
        findings.addAll(tlsAnalyzer.analyze(tls, now));

        Chain primary = httpsAvailable ? https : http;
        if (primary.hops().isEmpty()) {
            findings.add(FindingDraft.fail(FindingCategory.HTTP_RESPONSE, "RESPONSE_STATUS", Severity.INFORMATIONAL,
                    "Response could not be assessed",
                    "No HTTP response was received because the TLS connection failed and plain HTTP is unavailable. "
                            + "Header and cookie checks were skipped.",
                    https.error(), "Fix the TLS configuration and scan again."));
            return new ScanAssessment(findings, true, null);
        }

        FetchResult last = primary.last();
        boolean finalHttps = "https".equals(last.url().getScheme());
        applyResponse(sink, primary);

        findings.addAll(headerAnalyzer.analyze(last.headers(), finalHttps));
        findings.addAll(cookieAnalyzer.analyze(setCookieHeaders(primary), finalHttps));
        findings.addAll(disclosureAnalyzer.analyze(last.headers()));
        findings.addAll(responseAnalyzer.analyze(last, primary.totalTimeMs(),
                new ChainFacts(primary.hops().size() - 1, primary.tooManyRedirects(),
                        primary.blockedRedirect(), primary.error())));
        return new ScanAssessment(findings, true, null);
    }

    /**
     * Follows redirects manually. Each destination is re-validated (scheme, port,
     * DNS, IP ranges) before a request is made; disallowed destinations are not contacted.
     */
    Chain follow(URI start, boolean stopAtHttps) {
        List<FetchResult> hops = new ArrayList<>();
        URI current = start;
        for (int i = 0; i <= maxRedirects; i++) {
            ValidatedUrl target;
            try {
                target = validator.validate(current);
            } catch (UnsafeTargetException e) {
                String blocked = i == 0 ? null : current + " (" + e.getMessage() + ")";
                return new Chain(hops, null, e.getMessage(), blocked, false);
            }
            FetchResult result;
            try {
                result = fetcher.fetch(target);
            } catch (TlsHandshakeFailedException e) {
                return new Chain(hops, i == 0 ? e.getTlsInfo() : null, e.getMessage(), null, false);
            } catch (UnsafeTargetException e) {
                return new Chain(hops, null, e.getMessage(), i == 0 ? null : current.toString(), false);
            } catch (IOException e) {
                return new Chain(hops, null, describe(e), null, false);
            }
            hops.add(result);
            if (!result.isRedirect()) {
                return new Chain(hops, null, null, null, false);
            }
            URI next = resolve(current, result.location());
            if (next == null) {
                return new Chain(hops, null, "Invalid redirect location: " + result.location(), null, false);
            }
            if (stopAtHttps && "https".equalsIgnoreCase(next.getScheme())) {
                return new Chain(hops, null, null, null, false);
            }
            current = next;
        }
        return new Chain(hops, null, "Too many redirects", null, true);
    }

    private static boolean redirectsToHttps(FetchResult hop) {
        if (!hop.isRedirect()) {
            return false;
        }
        URI next = resolve(hop.url(), hop.location());
        return next != null && "https".equalsIgnoreCase(next.getScheme());
    }

    private static URI resolve(URI base, String location) {
        try {
            URI resolved = base.resolve(location.trim());
            return resolved.getScheme() == null ? null : resolved;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Same host and path with another scheme; a non-default port is kept only for the registered scheme. */
    private static URI withScheme(ValidatedUrl registered, String scheme) {
        boolean sameScheme = registered.https() == "https".equals(scheme);
        String host = registered.host().contains(":") ? "[" + registered.host() + "]" : registered.host();
        int defaultPort = registered.https() ? 443 : 80;
        String port = sameScheme && registered.port() != defaultPort ? ":" + registered.port() : "";
        return URI.create(scheme + "://" + host + port + registered.requestTarget());
    }

    private static List<String> setCookieHeaders(Chain chain) {
        List<String> values = new ArrayList<>();
        for (FetchResult hop : chain.hops()) {
            values.addAll(hop.headers().all("Set-Cookie"));
        }
        return values;
    }

    private static void applyTls(ScanRecord sink, TlsInfo tls, Instant now) {
        if (tls == null) {
            return;
        }
        sink.setTlsProtocol(tls.protocol());
        sink.setTlsCipherSuite(tls.cipherSuite());
        sink.setTlsSubject(truncate(tls.subject(), 500));
        sink.setTlsIssuer(truncate(tls.issuer(), 500));
        sink.setTlsValidFrom(tls.notBefore());
        sink.setTlsValidTo(tls.notAfter());
        sink.setTlsDaysRemaining(TlsAnalyzer.daysRemaining(tls, now));
        sink.setTlsTrusted(tls.trusted());
        sink.setTlsError(truncate(tls.error(), 500));
    }

    private static void applyResponse(ScanRecord sink, Chain chain) {
        FetchResult last = chain.last();
        sink.setFinalUrl(truncate(last.url().toString(), 500));
        sink.setHttpStatusCode(last.statusCode());
        sink.setResponseTimeMs(chain.totalTimeMs());
        sink.setContentType(truncate(last.headers().first("Content-Type"), 150));
        sink.setRedirectCount(chain.hops().size() - 1);
        StringBuilder sb = new StringBuilder();
        for (FetchResult hop : chain.hops()) {
            if (!sb.isEmpty()) {
                sb.append('\n');
            }
            sb.append(hop.statusCode()).append(' ').append(hop.url());
            if (hop.isRedirect()) {
                sb.append(" -> ").append(hop.location());
            }
        }
        sink.setRedirectChain(truncate(sb.toString(), 4000));
    }

    private static String describe(IOException e) {
        String type = e.getClass().getSimpleName();
        String message = e.getMessage();
        return message == null ? type : type + ": " + truncate(message, 300);
    }

    private static String truncate(String text, int max) {
        if (text == null || text.length() <= max) {
            return text;
        }
        return text.substring(0, max);
    }
}
