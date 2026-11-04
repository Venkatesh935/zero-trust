package com.zerotrust.service.scanner;

import static com.zerotrust.entity.FindingCategory.COOKIES;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.zerotrust.entity.Severity;

/**
 * Checks Secure, HttpOnly and SameSite attributes of cookies set by the site.
 * Cookie values are discarded immediately during parsing and never stored.
 */
public class CookieAnalyzer {

    private static final int MAX_COOKIES = 20;

    /** Security attributes of one cookie. The value is intentionally not part of this record. */
    public record CookieAttributes(String name, boolean secure, boolean httpOnly, String sameSite) {
    }

    public List<FindingDraft> analyze(List<String> setCookieHeaders, boolean https) {
        Map<String, CookieAttributes> cookies = new LinkedHashMap<>();
        for (String header : setCookieHeaders) {
            CookieAttributes attrs = parse(header);
            if (attrs != null && cookies.size() < MAX_COOKIES) {
                cookies.put(attrs.name(), attrs);
            }
        }

        List<FindingDraft> results = new ArrayList<>();
        if (cookies.isEmpty()) {
            results.add(FindingDraft.pass(COOKIES, "COOKIES_NONE", "No cookies set",
                    "The assessed responses did not set any cookies.", "0 cookies"));
            return results;
        }

        int secureCount = 0;
        for (CookieAttributes c : cookies.values()) {
            List<String> issues = new ArrayList<>();
            Severity severity = Severity.INFORMATIONAL;
            if (!c.secure()) {
                issues.add("missing Secure (cookie can be sent over unencrypted HTTP)");
                severity = https ? Severity.MEDIUM : Severity.LOW;
            }
            if (!c.httpOnly()) {
                issues.add("missing HttpOnly (readable by JavaScript, exposed to XSS)");
                severity = max(severity, Severity.LOW);
            }
            if (c.sameSite() == null) {
                issues.add("missing SameSite (relies on browser default for cross-site requests)");
                severity = max(severity, Severity.LOW);
            } else if (c.sameSite().equalsIgnoreCase("none") && !c.secure()) {
                issues.add("SameSite=None without Secure is rejected by modern browsers");
                severity = max(severity, Severity.MEDIUM);
            }
            if (issues.isEmpty()) {
                secureCount++;
                continue;
            }
            results.add(FindingDraft.fail(COOKIES, "COOKIE_" + c.name().toUpperCase(Locale.ROOT), severity,
                    "Cookie '" + c.name() + "' is missing security attributes",
                    "Cookie '" + c.name() + "': " + String.join("; ", issues) + ".",
                    describe(c),
                    "Set the cookie with Secure; HttpOnly; SameSite=Lax (or Strict). "
                            + "Omit HttpOnly only if client-side JavaScript must read the cookie."));
        }
        if (secureCount > 0) {
            results.add(FindingDraft.pass(COOKIES, "COOKIES_SECURE", secureCount + " cookie(s) correctly protected",
                    "These cookies set Secure, HttpOnly and SameSite.",
                    secureCount + " of " + cookies.size() + " cookies"));
        }
        return results;
    }

    /** Parses a Set-Cookie header keeping only the name and security attributes. */
    public static CookieAttributes parse(String setCookie) {
        if (setCookie == null || setCookie.isBlank()) {
            return null;
        }
        String[] parts = setCookie.split(";");
        int eq = parts[0].indexOf('=');
        String name = (eq >= 0 ? parts[0].substring(0, eq) : parts[0]).trim();
        // the value (parts[0] after '=') is deliberately ignored
        name = name.replaceAll("[^\\x21-\\x7e]", "");
        if (name.isEmpty()) {
            return null;
        }
        if (name.length() > 60) {
            name = name.substring(0, 60);
        }
        boolean secure = false;
        boolean httpOnly = false;
        String sameSite = null;
        for (int i = 1; i < parts.length; i++) {
            String attr = parts[i].trim();
            String lower = attr.toLowerCase(Locale.ROOT);
            if (lower.equals("secure")) {
                secure = true;
            } else if (lower.equals("httponly")) {
                httpOnly = true;
            } else if (lower.startsWith("samesite")) {
                int idx = attr.indexOf('=');
                sameSite = idx >= 0 ? attr.substring(idx + 1).trim() : "";
                if (sameSite.isEmpty()) {
                    sameSite = null;
                }
            }
        }
        return new CookieAttributes(name, secure, httpOnly, sameSite);
    }

    private static String describe(CookieAttributes c) {
        return "Secure: " + (c.secure() ? "yes" : "no")
                + ", HttpOnly: " + (c.httpOnly() ? "yes" : "no")
                + ", SameSite: " + (c.sameSite() == null ? "not set" : c.sameSite())
                + " (cookie value not recorded)";
    }

    private static Severity max(Severity a, Severity b) {
        return a.isAtLeast(b) ? a : b;
    }
}
