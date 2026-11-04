package com.zerotrust.service.scanner;

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

/**
 * TLS connection and leaf certificate details. When the handshake fails,
 * {@code trusted} is false, {@code error} explains why, and certificate
 * fields are filled from the chain the server presented (if any).
 */
public record TlsInfo(
        String protocol,
        String cipherSuite,
        String subject,
        String issuer,
        List<String> subjectAltNames,
        Instant notBefore,
        Instant notAfter,
        boolean trusted,
        String error) {

    public static TlsInfo fromSession(SSLSession session) {
        X509Certificate leaf = null;
        try {
            Certificate[] chain = session.getPeerCertificates();
            if (chain.length > 0 && chain[0] instanceof X509Certificate x509) {
                leaf = x509;
            }
        } catch (SSLPeerUnverifiedException e) {
            // leave certificate fields empty
        }
        return build(session.getProtocol(), session.getCipherSuite(), leaf, true, null);
    }

    public static TlsInfo failed(X509Certificate[] presentedChain, String error) {
        X509Certificate leaf = presentedChain != null && presentedChain.length > 0 ? presentedChain[0] : null;
        return build(null, null, leaf, false, error);
    }

    private static TlsInfo build(String protocol, String cipher, X509Certificate leaf, boolean trusted, String error) {
        if (leaf == null) {
            return new TlsInfo(protocol, cipher, null, null, List.of(), null, null, trusted, error);
        }
        return new TlsInfo(protocol, cipher,
                leaf.getSubjectX500Principal().getName(),
                leaf.getIssuerX500Principal().getName(),
                dnsNames(leaf),
                leaf.getNotBefore().toInstant(),
                leaf.getNotAfter().toInstant(),
                trusted, error);
    }

    private static List<String> dnsNames(X509Certificate cert) {
        List<String> names = new ArrayList<>();
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    // type 2 = dNSName, 7 = iPAddress
                    if (san.size() >= 2 && (Integer.valueOf(2).equals(san.get(0)) || Integer.valueOf(7).equals(san.get(0)))) {
                        names.add(String.valueOf(san.get(1)));
                    }
                    if (names.size() >= 20) {
                        break;
                    }
                }
            }
        } catch (CertificateParsingException e) {
            // ignore malformed SAN extension
        }
        return names;
    }
}
