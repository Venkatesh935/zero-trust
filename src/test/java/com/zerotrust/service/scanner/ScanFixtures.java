package com.zerotrust.service.scanner;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Builders for mock HTTP responses used by scanner tests.
 */
public final class ScanFixtures {

    private ScanFixtures() {
    }

    public static ResponseHeaders headers(String... nameValuePairs) {
        List<ResponseHeaders.Header> list = new ArrayList<>();
        for (int i = 0; i < nameValuePairs.length; i += 2) {
            list.add(new ResponseHeaders.Header(nameValuePairs[i], nameValuePairs[i + 1]));
        }
        return new ResponseHeaders(list);
    }

    public static TlsInfo validTls(Instant now, int daysRemaining) {
        return new TlsInfo("TLSv1.3", "TLS_AES_128_GCM_SHA256", "CN=www.example.com", "CN=Test CA,O=Test",
                List.of("www.example.com"), now.minus(Duration.ofDays(30)),
                now.plus(Duration.ofDays(daysRemaining)).plus(Duration.ofHours(1)), true, null);
    }

    public static FetchResult response(String url, int status, ResponseHeaders headers, TlsInfo tls) {
        return new FetchResult(URI.create(url), status, headers, 120, tls);
    }

    /** Headers of a well-configured site. */
    public static ResponseHeaders secureHeaders() {
        return headers(
                "Content-Type", "text/html; charset=utf-8",
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains",
                "Content-Security-Policy", "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
                "X-Frame-Options", "DENY",
                "X-Content-Type-Options", "nosniff",
                "Referrer-Policy", "strict-origin-when-cross-origin",
                "Permissions-Policy", "camera=(), microphone=()",
                "Set-Cookie", "SESSION=s3cr3t-session-value; Path=/; Secure; HttpOnly; SameSite=Lax");
    }
}
