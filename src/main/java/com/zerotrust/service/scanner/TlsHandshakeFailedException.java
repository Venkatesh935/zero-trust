package com.zerotrust.service.scanner;

import java.io.IOException;

/**
 * TLS handshake failed, usually because certificate validation failed.
 * Carries whatever certificate details the server presented.
 */
public class TlsHandshakeFailedException extends IOException {

    private final transient TlsInfo tlsInfo;

    public TlsHandshakeFailedException(TlsInfo tlsInfo, Throwable cause) {
        super(tlsInfo.error(), cause);
        this.tlsInfo = tlsInfo;
    }

    public TlsInfo getTlsInfo() {
        return tlsInfo;
    }
}
