package com.zerotrust.service.scanner;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

import org.springframework.stereotype.Component;

import com.zerotrust.config.ZeroTrustProperties;
import com.zerotrust.security.TargetUrlValidator;
import com.zerotrust.security.TargetUrlValidator.ValidatedUrl;

/**
 * Minimal, hardened HTTP/1.1 client used by the scanner.
 *
 * <p>Java's {@code HttpClient} resolves hostnames itself, so the address it
 * connects to could differ from the one the SSRF validator approved (DNS
 * rebinding). This client instead opens the socket to the exact validated IP
 * address, re-checks that address immediately before connecting, enforces
 * connect/read/overall deadlines, reads only the status line and headers
 * (bounded in size), and never reads the response body.</p>
 *
 * <p>TLS certificates are always verified with the JVM's default trust store
 * and hostname verification. Verification is never disabled; when it fails,
 * the presented certificate is captured only so it can be reported.</p>
 */
@Component
public class SocketHttpFetcher implements HttpFetcher {

    static final String USER_AGENT = "ZeroTrust-Passive-Scanner/1.0 (authorized security assessment)";
    private static final Pattern STATUS_LINE = Pattern.compile("^HTTP/\\d(?:\\.\\d)?\\s+(\\d{3})(?:\\s.*)?$");
    private static final int MAX_ADDRESSES_TRIED = 2;

    private final TargetUrlValidator validator;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final int maxHeaderBytes;
    private volatile X509ExtendedTrustManager defaultTrustManager;

    public SocketHttpFetcher(TargetUrlValidator validator, ZeroTrustProperties properties) {
        this.validator = validator;
        this.connectTimeoutMs = properties.getScanner().getConnectTimeoutMs();
        this.readTimeoutMs = properties.getScanner().getReadTimeoutMs();
        this.maxHeaderBytes = properties.getScanner().getMaxHeaderBytes();
    }

    @Override
    public FetchResult fetch(ValidatedUrl target) throws IOException {
        IOException lastError = null;
        int tried = 0;
        for (InetAddress address : target.addresses()) {
            if (tried++ >= MAX_ADDRESSES_TRIED) {
                break;
            }
            // Zero Trust: verify the destination again right before connecting.
            validator.assertAddressAllowed(address);
            try {
                return fetchFrom(target, address);
            } catch (TlsHandshakeFailedException e) {
                throw e; // certificate problems are a finding, not a reason to try another address
            } catch (IOException e) {
                lastError = e;
            }
        }
        throw lastError != null ? lastError : new IOException("No address available for " + target.host());
    }

    private FetchResult fetchFrom(ValidatedUrl target, InetAddress address) throws IOException {
        long start = System.nanoTime();
        long deadline = start + TimeUnit.MILLISECONDS.toNanos((long) connectTimeoutMs + readTimeoutMs);

        try (Socket plain = new Socket()) {
            plain.connect(new InetSocketAddress(address, target.port()), connectTimeoutMs);
            plain.setSoTimeout(readTimeoutMs);
            Socket socket = plain;
            TlsInfo tls = null;

            if (target.https()) {
                SSLSocket ssl = startTls(plain, target);
                tls = TlsInfo.fromSession(ssl.getSession());
                socket = ssl;
            }

            OutputStream out = socket.getOutputStream();
            out.write(buildRequest(target).getBytes(StandardCharsets.US_ASCII));
            out.flush();

            InputStream in = new BufferedInputStream(socket.getInputStream(), 4096);
            while (true) {
                String head = readHead(in, socket, deadline);
                List<String> lines = List.of(head.split("\r?\n"));
                Matcher status = STATUS_LINE.matcher(lines.get(0));
                if (!status.matches()) {
                    throw new IOException("Server did not return a valid HTTP response.");
                }
                int code = Integer.parseInt(status.group(1));
                if (code >= 100 && code < 200 && code != 101) {
                    continue; // skip interim responses such as 100 Continue
                }
                long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
                return new FetchResult(target.uri(), code, parseHeaders(lines), elapsedMs, tls);
            }
        }
    }

    private SSLSocket startTls(Socket plain, ValidatedUrl target) throws IOException {
        CapturingTrustManager trustManager = new CapturingTrustManager(defaultTrustManager());
        SSLSocket ssl;
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] {trustManager}, null);
            // The hostname (not the IP) is passed so SNI and certificate hostname checks use it.
            ssl = (SSLSocket) context.getSocketFactory().createSocket(plain, target.host(), target.port(), true);
        } catch (GeneralSecurityException e) {
            throw new IOException("TLS is not available in this Java runtime.", e);
        }
        SSLParameters params = ssl.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS");
        ssl.setSSLParameters(params);
        try {
            ssl.startHandshake();
        } catch (SSLException e) {
            throw new TlsHandshakeFailedException(
                    TlsInfo.failed(trustManager.capturedChain, describeTlsError(e)), e);
        }
        return ssl;
    }

    private String buildRequest(ValidatedUrl target) {
        return "GET " + target.requestTarget() + " HTTP/1.1\r\n"
                + "Host: " + target.hostHeader() + "\r\n"
                + "User-Agent: " + USER_AGENT + "\r\n"
                + "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
                + "Accept-Encoding: identity\r\n"
                + "Connection: close\r\n\r\n";
    }

    /** Reads bytes up to the blank line ending the headers, enforcing size and time limits. */
    private String readHead(InputStream in, Socket socket, long deadlineNanos) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(1024);
        int last1 = -1;
        int last2 = -1;
        int last3 = -1;
        while (true) {
            long remainingMs = TimeUnit.NANOSECONDS.toMillis(deadlineNanos - System.nanoTime());
            if (remainingMs <= 0) {
                throw new SocketTimeoutException("Response took too long.");
            }
            socket.setSoTimeout((int) Math.max(1, Math.min(readTimeoutMs, remainingMs)));
            int b = in.read();
            if (b == -1) {
                if (buffer.size() == 0) {
                    throw new IOException("Connection closed without a response.");
                }
                break;
            }
            buffer.write(b);
            if (buffer.size() > maxHeaderBytes) {
                throw new IOException("Response headers exceed the " + maxHeaderBytes + " byte limit.");
            }
            boolean crlfEnd = last3 == '\r' && last2 == '\n' && last1 == '\r' && b == '\n';
            boolean lfEnd = last1 == '\n' && b == '\n';
            if (crlfEnd || lfEnd) {
                break;
            }
            last3 = last2;
            last2 = last1;
            last1 = b;
        }
        return buffer.toString(StandardCharsets.ISO_8859_1).strip();
    }

    static ResponseHeaders parseHeaders(List<String> lines) {
        List<ResponseHeaders.Header> headers = new ArrayList<>();
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isEmpty()) {
                continue;
            }
            if ((line.charAt(0) == ' ' || line.charAt(0) == '\t') && !headers.isEmpty()) {
                // obsolete line folding: continuation of the previous header
                ResponseHeaders.Header prev = headers.remove(headers.size() - 1);
                headers.add(new ResponseHeaders.Header(prev.name(), prev.value() + " " + line.strip()));
                continue;
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            headers.add(new ResponseHeaders.Header(line.substring(0, colon).strip(), line.substring(colon + 1).strip()));
        }
        return new ResponseHeaders(headers);
    }

    private static String describeTlsError(SSLException e) {
        Throwable root = e;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        String message = root.getMessage() != null ? root.getMessage() : e.getMessage();
        if (message == null) {
            message = e.getClass().getSimpleName();
        }
        return message.length() > 400 ? message.substring(0, 400) : message;
    }

    private X509ExtendedTrustManager defaultTrustManager() throws IOException {
        X509ExtendedTrustManager tm = defaultTrustManager;
        if (tm != null) {
            return tm;
        }
        try {
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init((KeyStore) null);
            for (TrustManager candidate : factory.getTrustManagers()) {
                if (candidate instanceof X509ExtendedTrustManager extended) {
                    defaultTrustManager = extended;
                    return extended;
                }
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("Unable to load the default trust store.", e);
        }
        throw new IOException("No X509 trust manager available.");
    }

    /**
     * Delegates every decision to the JVM's default trust manager (full chain and
     * hostname verification). It only records the chain the server presented so
     * that details of an invalid certificate can be reported.
     */
    static final class CapturingTrustManager extends X509ExtendedTrustManager {

        private final X509ExtendedTrustManager delegate;
        private volatile X509Certificate[] capturedChain;

        CapturingTrustManager(X509ExtendedTrustManager delegate) {
            this.delegate = delegate;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            capturedChain = chain;
            delegate.checkServerTrusted(chain, authType, socket);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            capturedChain = chain;
            delegate.checkServerTrusted(chain, authType, engine);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            capturedChain = chain;
            delegate.checkServerTrusted(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            delegate.checkClientTrusted(chain, authType, socket);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            delegate.checkClientTrusted(chain, authType, engine);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }
    }
}
