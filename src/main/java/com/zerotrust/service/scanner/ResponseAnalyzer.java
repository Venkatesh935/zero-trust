package com.zerotrust.service.scanner;

import static com.zerotrust.entity.FindingCategory.HTTP_RESPONSE;

import java.util.ArrayList;
import java.util.List;

import com.zerotrust.entity.Severity;

/**
 * Evaluates status code, response time, content type and redirect behaviour.
 */
public class ResponseAnalyzer {

    public static final long SLOW_RESPONSE_MS = 3000;

    /** Facts about the followed redirect chain. */
    public record ChainFacts(int redirectCount, boolean tooManyRedirects, String blockedRedirect, String error) {
    }

    public List<FindingDraft> analyze(FetchResult last, long totalTimeMs, ChainFacts chain) {
        List<FindingDraft> results = new ArrayList<>();
        int code = last.statusCode();
        String evidence = "HTTP " + code + " from " + last.url();

        if (code >= 200 && code < 300) {
            results.add(FindingDraft.pass(HTTP_RESPONSE, "RESPONSE_STATUS", "Website responded successfully",
                    "The final response returned a success status.", evidence));
        } else if (code >= 500) {
            results.add(FindingDraft.fail(HTTP_RESPONSE, "RESPONSE_STATUS", Severity.MEDIUM, "Server error response",
                    "The website returned a server error, which may indicate an outage or misconfiguration.",
                    evidence, "Check the server logs and application health."));
        } else if (code >= 400) {
            results.add(FindingDraft.fail(HTTP_RESPONSE, "RESPONSE_STATUS", Severity.INFORMATIONAL, "Client error response",
                    "The website returned a client error (for example access denied or not found). Security headers "
                            + "were assessed on this response.",
                    evidence, "Verify that the registered URL points to the intended page."));
        } else if (code >= 300) {
            results.add(FindingDraft.fail(HTTP_RESPONSE, "RESPONSE_STATUS", Severity.LOW, "Redirect was not completed",
                    "The final response is still a redirect, so the destination page was not assessed.",
                    evidence + (last.location() != null ? " -> " + last.location() : ""),
                    "Register the final destination URL or fix the redirect chain."));
        }

        if (chain.tooManyRedirects()) {
            results.add(FindingDraft.fail(HTTP_RESPONSE, "RESPONSE_REDIRECTS", Severity.MEDIUM, "Too many redirects",
                    "The redirect chain exceeded the scanner's limit, which may indicate a redirect loop.",
                    chain.redirectCount() + " redirects followed", "Reduce the redirect chain to at most one or two steps."));
        }
        if (chain.blockedRedirect() != null) {
            results.add(FindingDraft.fail(HTTP_RESPONSE, "RESPONSE_REDIRECT_BLOCKED", Severity.MEDIUM,
                    "Redirect to a disallowed destination",
                    "The website redirected to a destination that the SSRF protection does not allow "
                            + "(internal address, unsupported port or scheme). It was not followed.",
                    chain.blockedRedirect(), "Ensure redirects only point to public HTTPS URLs."));
        }

        if (totalTimeMs > SLOW_RESPONSE_MS) {
            results.add(FindingDraft.fail(HTTP_RESPONSE, "RESPONSE_TIME", Severity.LOW, "Slow response",
                    "The website took more than " + SLOW_RESPONSE_MS + " ms to respond, which can indicate overload.",
                    totalTimeMs + " ms", "Investigate server performance and caching."));
        } else {
            results.add(FindingDraft.pass(HTTP_RESPONSE, "RESPONSE_TIME", "Response time acceptable",
                    "The website responded within " + SLOW_RESPONSE_MS + " ms.", totalTimeMs + " ms"));
        }

        String contentType = last.headers().first("Content-Type");
        if (contentType == null && code >= 200 && code < 300) {
            results.add(FindingDraft.fail(HTTP_RESPONSE, "RESPONSE_CONTENT_TYPE", Severity.LOW, "Content-Type header missing",
                    "Without a declared content type browsers guess (sniff) it, which can lead to content being "
                            + "interpreted unsafely.",
                    "Not present", "Always send an accurate Content-Type header including the charset."));
        }
        return results;
    }
}
