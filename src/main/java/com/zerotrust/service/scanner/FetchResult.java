package com.zerotrust.service.scanner;

import java.net.URI;

/**
 * Status line and headers of one HTTP response. The response body is never read.
 */
public record FetchResult(
        URI url,
        int statusCode,
        ResponseHeaders headers,
        long responseTimeMs,
        TlsInfo tls) {

    public boolean isRedirect() {
        return (statusCode == 301 || statusCode == 302 || statusCode == 303
                || statusCode == 307 || statusCode == 308) && headers.first("Location") != null;
    }

    public String location() {
        return headers.first("Location");
    }
}
