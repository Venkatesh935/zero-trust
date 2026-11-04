package com.zerotrust.service.scanner;

import static com.zerotrust.entity.FindingCategory.TLS;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import com.zerotrust.entity.Severity;

/**
 * Evaluates certificate trust, expiry and negotiated protocol version.
 */
public class TlsAnalyzer {

    public static final int EXPIRY_HIGH_DAYS = 14;
    public static final int EXPIRY_MEDIUM_DAYS = 30;

    public List<FindingDraft> analyze(TlsInfo tls, Instant now) {
        List<FindingDraft> results = new ArrayList<>();
        if (tls == null) {
            results.add(FindingDraft.fail(TLS, "TLS_NOT_ASSESSED", Severity.INFORMATIONAL,
                    "TLS certificate not assessed",
                    "No HTTPS connection could be made, so no certificate was available to evaluate.",
                    "HTTPS unavailable", "Enable HTTPS with a certificate from a trusted certificate authority."));
            return results;
        }

        if (tls.trusted()) {
            results.add(FindingDraft.pass(TLS, "TLS_TRUST", "Certificate is trusted",
                    "The certificate chain is valid, issued by a trusted authority and matches the hostname.",
                    "Issuer: " + tls.issuer()));
        } else {
            results.add(FindingDraft.fail(TLS, "TLS_TRUST", Severity.CRITICAL, "Certificate validation failed",
                    "Browsers will show a security warning. The certificate may be expired, self-signed, issued by "
                            + "an untrusted authority or not match the hostname.",
                    tls.error(), "Install a valid certificate from a trusted CA (e.g. Let's Encrypt) covering this hostname."));
        }

        Long days = daysRemaining(tls, now);
        if (days != null) {
            String evidence = "Valid until " + tls.notAfter() + " (" + days + " days remaining)";
            if (days < 0) {
                results.add(FindingDraft.fail(TLS, "TLS_EXPIRY", Severity.CRITICAL, "Certificate has expired",
                        "The certificate expired " + (-days) + " day(s) ago.", evidence,
                        "Renew the certificate immediately and enable automatic renewal."));
            } else if (days <= EXPIRY_HIGH_DAYS) {
                results.add(FindingDraft.fail(TLS, "TLS_EXPIRY", Severity.HIGH, "Certificate expires very soon",
                        "The certificate expires in " + days + " day(s).", evidence,
                        "Renew the certificate now and automate renewal."));
            } else if (days <= EXPIRY_MEDIUM_DAYS) {
                results.add(FindingDraft.fail(TLS, "TLS_EXPIRY", Severity.MEDIUM, "Certificate expires soon",
                        "The certificate expires in " + days + " days.", evidence,
                        "Plan certificate renewal and verify automatic renewal is configured."));
            } else {
                results.add(FindingDraft.pass(TLS, "TLS_EXPIRY", "Certificate validity period OK",
                        "The certificate is valid for more than " + EXPIRY_MEDIUM_DAYS + " days.", evidence));
            }
        }

        if (tls.protocol() != null) {
            String protocol = tls.protocol();
            if (protocol.equals("TLSv1.3") || protocol.equals("TLSv1.2")) {
                results.add(FindingDraft.pass(TLS, "TLS_PROTOCOL", "Modern TLS protocol negotiated",
                        protocol + " was negotiated.", protocol + " / " + tls.cipherSuite()));
            } else {
                results.add(FindingDraft.fail(TLS, "TLS_PROTOCOL", Severity.HIGH, "Outdated TLS protocol negotiated",
                        protocol + " is deprecated and has known weaknesses.", protocol,
                        "Disable TLS 1.0/1.1 and support TLS 1.2 and TLS 1.3 only."));
            }
        }
        return results;
    }

    public static Long daysRemaining(TlsInfo tls, Instant now) {
        if (tls == null || tls.notAfter() == null) {
            return null;
        }
        return Math.floorDiv(Duration.between(now, tls.notAfter()).toHours(), 24);
    }
}
