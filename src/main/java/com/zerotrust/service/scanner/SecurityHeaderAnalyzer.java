package com.zerotrust.service.scanner;

import static com.zerotrust.entity.FindingCategory.SECURITY_HEADERS;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.zerotrust.entity.Severity;

/**
 * Checks presence and basic configuration of the six key HTTP security headers.
 */
public class SecurityHeaderAnalyzer {

    public static final String HSTS = "Strict-Transport-Security";
    public static final String CSP = "Content-Security-Policy";
    public static final String XFO = "X-Frame-Options";
    public static final String XCTO = "X-Content-Type-Options";
    public static final String REFERRER = "Referrer-Policy";
    public static final String PERMISSIONS = "Permissions-Policy";

    private static final long SIX_MONTHS_SECONDS = 15_552_000L;
    private static final Pattern MAX_AGE = Pattern.compile("max-age\\s*=\\s*\"?(\\d+)\"?", Pattern.CASE_INSENSITIVE);

    public List<FindingDraft> analyze(ResponseHeaders headers, boolean https) {
        List<FindingDraft> results = new ArrayList<>();
        results.add(checkHsts(headers.first(HSTS), https));
        results.add(checkCsp(headers.first(CSP), headers.first("Content-Security-Policy-Report-Only")));
        results.add(checkFrameOptions(headers.first(XFO), headers.first(CSP)));
        results.add(checkContentTypeOptions(headers.first(XCTO)));
        results.add(checkReferrerPolicy(headers.first(REFERRER)));
        results.add(checkPermissionsPolicy(headers.first(PERMISSIONS), headers.first("Feature-Policy")));
        return results;
    }

    FindingDraft checkHsts(String value, boolean https) {
        String key = "HEADER_HSTS";
        if (!https) {
            return FindingDraft.fail(SECURITY_HEADERS, key, Severity.INFORMATIONAL, HSTS + " not applicable",
                    "HSTS can only be delivered over HTTPS. The site was assessed over plain HTTP.",
                    value == null ? "Not present" : value,
                    "Enable HTTPS first, then add Strict-Transport-Security: max-age=31536000; includeSubDomains.");
        }
        if (value == null) {
            return FindingDraft.fail(SECURITY_HEADERS, key, Severity.HIGH, HSTS + " header missing",
                    "Without HSTS, browsers may first connect over plain HTTP, allowing SSL-stripping "
                            + "and man-in-the-middle attacks.",
                    "Not present",
                    "Add Strict-Transport-Security: max-age=31536000; includeSubDomains to HTTPS responses.");
        }
        Matcher m = MAX_AGE.matcher(value);
        if (!m.find()) {
            return FindingDraft.fail(SECURITY_HEADERS, key, Severity.MEDIUM, HSTS + " has no valid max-age",
                    "The header is present but browsers ignore it without a valid max-age directive.",
                    value, "Set a max-age of at least 15552000 seconds (180 days), e.g. max-age=31536000.");
        }
        long maxAge;
        try {
            maxAge = Long.parseLong(m.group(1));
        } catch (NumberFormatException e) {
            maxAge = Long.MAX_VALUE;
        }
        if (maxAge == 0) {
            return FindingDraft.fail(SECURITY_HEADERS, key, Severity.MEDIUM, HSTS + " disabled (max-age=0)",
                    "max-age=0 instructs browsers to remove the HSTS policy.",
                    value, "Use max-age=31536000 to keep HSTS enforced.");
        }
        if (maxAge < SIX_MONTHS_SECONDS) {
            return FindingDraft.fail(SECURITY_HEADERS, key, Severity.LOW, HSTS + " max-age is short",
                    "A short max-age reduces the protection window of HSTS (recommended: at least 180 days).",
                    value, "Increase max-age to at least 15552000; 31536000 (one year) is recommended.");
        }
        String note = value.toLowerCase(Locale.ROOT).contains("includesubdomains")
                ? "includeSubDomains is set."
                : "Consider adding includeSubDomains.";
        return FindingDraft.pass(SECURITY_HEADERS, key, HSTS + " configured",
                "HSTS is enabled with an adequate max-age. " + note, value);
    }

    FindingDraft checkCsp(String value, String reportOnly) {
        String key = "HEADER_CSP";
        if (value == null) {
            if (reportOnly != null) {
                return FindingDraft.fail(SECURITY_HEADERS, key, Severity.MEDIUM, CSP + " only in report-only mode",
                        "A report-only policy is monitored but not enforced, so it does not block attacks.",
                        "Content-Security-Policy-Report-Only: " + reportOnly,
                        "After reviewing reports, deploy the policy using the enforcing Content-Security-Policy header.");
            }
            return FindingDraft.fail(SECURITY_HEADERS, key, Severity.MEDIUM, CSP + " header missing",
                    "A Content Security Policy restricts where scripts and other resources may load from, "
                            + "reducing the impact of cross-site scripting (XSS).",
                    "Not present",
                    "Define a policy such as: default-src 'self'; script-src 'self'; object-src 'none'; "
                            + "frame-ancestors 'self'; base-uri 'self'.");
        }
        String scriptSources = directive(value, "script-src");
        if (scriptSources == null) {
            scriptSources = directive(value, "default-src");
        }
        List<String> issues = new ArrayList<>();
        Severity severity = Severity.INFORMATIONAL;
        if (scriptSources == null) {
            issues.add("no script-src or default-src directive, so scripts are not restricted");
            severity = Severity.LOW;
        } else {
            List<String> tokens = Arrays.asList(scriptSources.toLowerCase(Locale.ROOT).split("\\s+"));
            boolean hasNonceOrHash = tokens.stream().anyMatch(t -> t.startsWith("'nonce-") || t.startsWith("'sha"));
            if (tokens.contains("*") || tokens.contains("http:") || tokens.contains("https:")) {
                issues.add("script sources allow any host (wildcard or scheme-only source)");
                severity = Severity.MEDIUM;
            }
            if (tokens.contains("'unsafe-inline'") && !hasNonceOrHash) {
                issues.add("'unsafe-inline' allows inline scripts");
                severity = max(severity, Severity.LOW);
            }
            if (tokens.contains("'unsafe-eval'")) {
                issues.add("'unsafe-eval' allows eval()");
                severity = max(severity, Severity.LOW);
            }
        }
        if (issues.isEmpty()) {
            return FindingDraft.pass(SECURITY_HEADERS, key, CSP + " configured",
                    "A Content Security Policy restricting script sources is enforced.", value);
        }
        return FindingDraft.fail(SECURITY_HEADERS, key, severity, CSP + " is weak",
                "The policy is present but: " + String.join("; ", issues) + ".", value,
                "Remove 'unsafe-inline'/'unsafe-eval' and wildcard sources; use nonces or hashes for required inline scripts.");
    }

    FindingDraft checkFrameOptions(String value, String csp) {
        String key = "HEADER_XFO";
        String frameAncestors = csp == null ? null : directive(csp, "frame-ancestors");
        if (frameAncestors != null) {
            return FindingDraft.pass(SECURITY_HEADERS, key, "Clickjacking protection configured",
                    "Framing is controlled by the CSP frame-ancestors directive, which supersedes X-Frame-Options.",
                    "frame-ancestors " + frameAncestors + (value != null ? " | X-Frame-Options: " + value : ""));
        }
        if (value == null) {
            return FindingDraft.fail(SECURITY_HEADERS, key, Severity.MEDIUM, XFO + " header missing",
                    "Without X-Frame-Options or CSP frame-ancestors, the site can be embedded in frames on other "
                            + "sites, enabling clickjacking attacks.",
                    "Not present",
                    "Add X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'self'.");
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        if (normalized.equals("DENY") || normalized.equals("SAMEORIGIN")) {
            return FindingDraft.pass(SECURITY_HEADERS, key, XFO + " configured",
                    "Framing by other sites is restricted.", value);
        }
        if (normalized.startsWith("ALLOW-FROM")) {
            return FindingDraft.fail(SECURITY_HEADERS, key, Severity.LOW, XFO + " uses deprecated ALLOW-FROM",
                    "Modern browsers ignore ALLOW-FROM, leaving the site without clickjacking protection.",
                    value, "Use CSP frame-ancestors to list allowed embedding origins.");
        }
        return FindingDraft.fail(SECURITY_HEADERS, key, Severity.LOW, XFO + " has an invalid value",
                "Browsers ignore unrecognized X-Frame-Options values.", value,
                "Use X-Frame-Options: DENY or SAMEORIGIN.");
    }

    FindingDraft checkContentTypeOptions(String value) {
        String key = "HEADER_XCTO";
        if (value == null) {
            return FindingDraft.fail(SECURITY_HEADERS, key, Severity.LOW, XCTO + " header missing",
                    "Browsers may MIME-sniff responses and interpret files as a different content type.",
                    "Not present", "Add X-Content-Type-Options: nosniff.");
        }
        if (!value.trim().equalsIgnoreCase("nosniff")) {
            return FindingDraft.fail(SECURITY_HEADERS, key, Severity.LOW, XCTO + " has an invalid value",
                    "The only valid value is 'nosniff'.", value, "Set X-Content-Type-Options: nosniff.");
        }
        return FindingDraft.pass(SECURITY_HEADERS, key, XCTO + " configured",
                "MIME-type sniffing is disabled.", value);
    }

    FindingDraft checkReferrerPolicy(String value) {
        String key = "HEADER_REFERRER";
        if (value == null) {
            return FindingDraft.fail(SECURITY_HEADERS, key, Severity.LOW, REFERRER + " header missing",
                    "Without an explicit policy, browser defaults decide how much of the URL is shared with "
                            + "other sites in the Referer header.",
                    "Not present", "Add Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).");
        }
        String[] parts = value.split(",");
        String effective = parts[parts.length - 1].trim().toLowerCase(Locale.ROOT);
        if (effective.equals("unsafe-url") || effective.equals("no-referrer-when-downgrade")) {
            return FindingDraft.fail(SECURITY_HEADERS, key, Severity.LOW, REFERRER + " leaks full URLs",
                    "'" + effective + "' sends the full URL (including path and query) to other sites.",
                    value, "Use strict-origin-when-cross-origin, same-origin or no-referrer.");
        }
        return FindingDraft.pass(SECURITY_HEADERS, key, REFERRER + " configured",
                "Referrer information shared with other sites is limited.", value);
    }

    FindingDraft checkPermissionsPolicy(String value, String featurePolicy) {
        String key = "HEADER_PERMISSIONS";
        if (value == null) {
            String evidence = featurePolicy != null ? "Only deprecated Feature-Policy present: " + featurePolicy : "Not present";
            return FindingDraft.fail(SECURITY_HEADERS, key, Severity.LOW, PERMISSIONS + " header missing",
                    "Permissions-Policy restricts powerful browser features (camera, microphone, geolocation) "
                            + "for the site and embedded content.",
                    evidence, "Add e.g. Permissions-Policy: camera=(), microphone=(), geolocation=().");
        }
        return FindingDraft.pass(SECURITY_HEADERS, key, PERMISSIONS + " configured",
                "Browser feature permissions are explicitly restricted.", value);
    }

    /** Returns the source list of a CSP directive, or null when absent. */
    static String directive(String policy, String name) {
        for (String part : policy.split(";")) {
            String trimmed = part.trim();
            String lower = trimmed.toLowerCase(Locale.ROOT);
            if (lower.equals(name) || lower.startsWith(name + " ")) {
                return trimmed.substring(name.length()).trim();
            }
        }
        return null;
    }

    private static Severity max(Severity a, Severity b) {
        return a.isAtLeast(b) ? a : b;
    }
}
