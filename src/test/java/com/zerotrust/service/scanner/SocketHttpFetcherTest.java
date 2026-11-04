package com.zerotrust.service.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.zerotrust.config.ZeroTrustProperties;
import com.zerotrust.exception.UnsafeTargetException;
import com.zerotrust.security.TargetUrlValidator;

/**
 * Exercises the hardened HTTP client against a local socket server. The SSRF
 * validator is relaxed only inside this test so that loopback can be used.
 */
class SocketHttpFetcherTest {

    private ServerSocket server;
    private Thread serverThread;

    @AfterEach
    void stop() throws IOException {
        if (server != null) {
            server.close();
        }
    }

    /** Starts a one-shot server that records the request and writes {@code rawResponse}. */
    private int serve(String rawResponse, AtomicReference<String> requestSeen, long delayMs) throws IOException {
        server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        serverThread = new Thread(() -> {
            try (Socket s = server.accept()) {
                InputStream in = s.getInputStream();
                StringBuilder req = new StringBuilder();
                while (!req.toString().endsWith("\r\n\r\n")) {
                    int b = in.read();
                    if (b < 0) {
                        break;
                    }
                    req.append((char) b);
                }
                if (requestSeen != null) {
                    requestSeen.set(req.toString());
                }
                if (delayMs > 0) {
                    Thread.sleep(delayMs);
                }
                OutputStream out = s.getOutputStream();
                out.write(rawResponse.getBytes(StandardCharsets.ISO_8859_1));
                out.flush();
            } catch (IOException | InterruptedException e) {
                // server closed
            }
        });
        serverThread.start();
        return server.getLocalPort();
    }

    private static ZeroTrustProperties props(int readTimeoutMs, int maxHeaderBytes) {
        ZeroTrustProperties p = new ZeroTrustProperties();
        p.getScanner().setConnectTimeoutMs(2000);
        p.getScanner().setReadTimeoutMs(readTimeoutMs);
        p.getScanner().setMaxHeaderBytes(maxHeaderBytes);
        return p;
    }

    /** Test-only validator that allows loopback and any port. */
    private static TargetUrlValidator loopbackAllowed(int port) {
        return new TargetUrlValidator(host -> new InetAddress[] {InetAddress.getLoopbackAddress()}, Set.of(port)) {
            @Override
            protected boolean isBlockedAddress(InetAddress address) {
                return false;
            }
        };
    }

    @Test
    void parsesStatusAndHeadersAndSendsMinimalRequest() throws Exception {
        AtomicReference<String> request = new AtomicReference<>();
        int port = serve("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: a=1; Secure\r\n"
                + "Set-Cookie: b=2; HttpOnly\r\nX-Folded: part1\r\n  part2\r\nServer: test\r\n\r\n<html>body never read</html>",
                request, 0);
        TargetUrlValidator validator = loopbackAllowed(port);
        SocketHttpFetcher fetcher = new SocketHttpFetcher(validator, props(3000, 65536));

        FetchResult r = fetcher.fetch(validator.validate("http://scanner-test.example.com:" + port + "/page?x=1"));

        assertThat(r.statusCode()).isEqualTo(200);
        assertThat(r.headers().first("content-type")).isEqualTo("text/html");
        assertThat(r.headers().all("Set-Cookie")).containsExactly("a=1; Secure", "b=2; HttpOnly");
        assertThat(r.headers().first("X-Folded")).isEqualTo("part1 part2");
        assertThat(r.tls()).isNull();
        assertThat(request.get()).startsWith("GET /page?x=1 HTTP/1.1\r\n")
                .contains("Host: scanner-test.example.com:" + port)
                .contains("Connection: close")
                .contains(SocketHttpFetcher.USER_AGENT);
    }

    @Test
    void redirectResponseExposesLocation() throws Exception {
        int port = serve("HTTP/1.1 301 Moved\r\nLocation: https://www.example.com/\r\n\r\n", null, 0);
        TargetUrlValidator validator = loopbackAllowed(port);
        FetchResult r = new SocketHttpFetcher(validator, props(3000, 65536))
                .fetch(validator.validate("http://scanner-test.example.com:" + port + "/"));
        assertThat(r.isRedirect()).isTrue();
        assertThat(r.location()).isEqualTo("https://www.example.com/");
    }

    @Test
    void oversizedHeadersAreRejected() throws Exception {
        String huge = "X-Big: " + "a".repeat(5000) + "\r\n";
        int port = serve("HTTP/1.1 200 OK\r\n" + huge + "\r\n", null, 0);
        TargetUrlValidator validator = loopbackAllowed(port);
        SocketHttpFetcher fetcher = new SocketHttpFetcher(validator, props(3000, 1024));
        assertThatThrownBy(() -> fetcher.fetch(validator.validate("http://scanner-test.example.com:" + port + "/")))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("limit");
    }

    @Test
    void slowServerTimesOut() throws Exception {
        int port = serve("HTTP/1.1 200 OK\r\n\r\n", null, 3000);
        TargetUrlValidator validator = loopbackAllowed(port);
        SocketHttpFetcher fetcher = new SocketHttpFetcher(validator, props(500, 65536));
        assertThatThrownBy(() -> fetcher.fetch(validator.validate("http://scanner-test.example.com:" + port + "/")))
                .isInstanceOf(SocketTimeoutException.class);
    }

    @Test
    void nonHttpResponseIsRejected() throws Exception {
        int port = serve("SSH-2.0-OpenSSH_9.0\r\n\r\n", null, 0);
        TargetUrlValidator validator = loopbackAllowed(port);
        assertThatThrownBy(() -> new SocketHttpFetcher(validator, props(3000, 65536))
                .fetch(validator.validate("http://scanner-test.example.com:" + port + "/")))
                .isInstanceOf(IOException.class);
    }

    @Test
    void productionValidatorRefusesToConnectToLoopback() throws Exception {
        int port = serve("HTTP/1.1 200 OK\r\n\r\n", null, 0);
        // Simulates DNS rebinding: the address list handed to the fetcher contains loopback.
        TargetUrlValidator strict = new TargetUrlValidator(h -> new InetAddress[] {InetAddress.getByName("93.184.216.34")}, Set.of(port));
        TargetUrlValidator.ValidatedUrl tampered = new TargetUrlValidator.ValidatedUrl(
                java.net.URI.create("http://scanner-test.example.com:" + port + "/"), "scanner-test.example.com", port, false,
                List.of(InetAddress.getLoopbackAddress()));
        SocketHttpFetcher fetcher = new SocketHttpFetcher(strict, props(3000, 65536));
        assertThatThrownBy(() -> fetcher.fetch(tampered)).isInstanceOf(UnsafeTargetException.class);
    }
}
