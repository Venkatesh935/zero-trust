package com.zerotrust.service.scanner;

import static com.zerotrust.entity.FindingCategory.HTTPS;

import java.util.ArrayList;
import java.util.List;

import com.zerotrust.entity.Severity;

/**
 * Evaluates HTTPS availability, HTTP-to-HTTPS redirection and downgrade redirects.
 */
public class HttpsAnalyzer {

    /** Facts gathered by the scanner about the HTTP and HTTPS endpoints. */
    public record HttpsFacts(
            boolean registeredAsHttps,
            boolean httpsAvailable,
            boolean tlsHandshakeFailed,
            boolean httpAvailable,
            Boolean httpRedirectsToHttps,
            boolean downgradeToHttp) {
    }

    public List<FindingDraft> analyze(HttpsFacts facts) {
        List<FindingDraft> results = new ArrayList<>();

        if (facts.httpsAvailable()) {
            results.add(FindingDraft.pass(HTTPS, "HTTPS_AVAILABLE", "HTTPS is available",
                    "The website accepts encrypted HTTPS connections with a trusted certificate.", "HTTPS connection succeeded"));
        } else if (facts.tlsHandshakeFailed()) {
            results.add(FindingDraft.fail(HTTPS, "HTTPS_AVAILABLE", Severity.HIGH, "HTTPS cannot be established securely",
                    "The server offers TLS, but the connection could not be verified, so browsers will warn users.",
                    "TLS handshake / certificate verification failed",
                    "Fix the TLS certificate configuration so that HTTPS connections validate successfully."));
        } else {
            results.add(FindingDraft.fail(HTTPS, "HTTPS_AVAILABLE", Severity.CRITICAL, "HTTPS is not available",
                    "All traffic, including credentials and session cookies, is sent unencrypted and can be read "
                            + "or modified by anyone on the network path.",
                    "No HTTPS response on port 443",
                    "Obtain a TLS certificate (e.g. free from Let's Encrypt) and serve the site over HTTPS."));
        }

        if (!facts.httpAvailable()) {
            results.add(FindingDraft.pass(HTTPS, "HTTP_REDIRECT", "Plain HTTP not served",
                    "The plain HTTP endpoint did not respond, so content is not served unencrypted.", "No HTTP response"));
        } else if (Boolean.TRUE.equals(facts.httpRedirectsToHttps())) {
            results.add(FindingDraft.pass(HTTPS, "HTTP_REDIRECT", "HTTP redirects to HTTPS",
                    "Requests over plain HTTP are redirected to HTTPS.", "HTTP responds with a redirect to https://"));
        } else if (facts.httpsAvailable()) {
            results.add(FindingDraft.fail(HTTPS, "HTTP_REDIRECT", Severity.MEDIUM, "HTTP does not redirect to HTTPS",
                    "The site is still served over unencrypted HTTP although HTTPS is available.",
                    "HTTP responds without redirecting to https://",
                    "Configure a permanent (301) redirect from http:// to https:// and enable HSTS."));
        } else {
            results.add(FindingDraft.fail(HTTPS, "HTTP_REDIRECT", Severity.INFORMATIONAL, "Site served only over HTTP",
                    "The site is served over HTTP and cannot redirect because HTTPS is not working.",
                    "HTTP responds without redirecting to https://",
                    "Enable HTTPS first, then redirect all HTTP traffic to HTTPS."));
        }

        if (facts.downgradeToHttp()) {
            results.add(FindingDraft.fail(HTTPS, "HTTPS_DOWNGRADE", Severity.HIGH, "HTTPS redirects to plain HTTP",
                    "A redirect sends visitors from HTTPS back to unencrypted HTTP, removing transport protection.",
                    "Redirect chain contains an https:// to http:// step",
                    "Ensure every redirect target uses https://."));
        }

        if (!facts.registeredAsHttps() && facts.httpsAvailable()) {
            results.add(FindingDraft.fail(HTTPS, "HTTPS_REGISTERED_URL", Severity.INFORMATIONAL,
                    "Target registered with an http:// URL",
                    "HTTPS is available; consider registering the https:// URL.", "Registered scheme: http",
                    "Update the registered URL to use https://."));
        }
        return results;
    }
}
