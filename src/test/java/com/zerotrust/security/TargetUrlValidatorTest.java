package com.zerotrust.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.zerotrust.exception.UnsafeTargetException;
import com.zerotrust.security.TargetUrlValidator.ValidatedUrl;

/**
 * SSRF protection and URL validation, using a fake DNS resolver (no network access).
 */
class TargetUrlValidatorTest {

    private static final Map<String, String[]> DNS = Map.of(
            "www.example.com", new String[] {"93.184.216.34"},
            "rebind.example.com", new String[] {"93.184.216.34", "127.0.0.1"},
            "private.example.com", new String[] {"192.168.1.20"},
            "metadata.example.com", new String[] {"169.254.169.254"},
            "v6.example.com", new String[] {"2606:2800:220:1:248:1893:25c8:1946"},
            "ula.example.com", new String[] {"fd00::1"});

    private final TargetUrlValidator validator = new TargetUrlValidator(TargetUrlValidatorTest::resolve,
            Set.of(80, 443, 8080, 8443));

    static InetAddress[] resolve(String host) throws UnknownHostException {
        if (host.matches("[0-9.]+") || host.contains(":")) {
            return new InetAddress[] {InetAddress.getByName(host)}; // IP literal, no lookup
        }
        String[] ips = DNS.get(host);
        if (ips == null) {
            throw new UnknownHostException(host);
        }
        InetAddress[] result = new InetAddress[ips.length];
        for (int i = 0; i < ips.length; i++) {
            result[i] = InetAddress.getByName(ips[i]);
        }
        return result;
    }

    @Test
    void acceptsPublicHttpsUrlAndNormalizesIt() {
        ValidatedUrl url = validator.validate("HTTPS://WWW.Example.com:443/path?q=1#frag");
        assertThat(url.uri().toString()).isEqualTo("https://www.example.com/path?q=1");
        assertThat(url.host()).isEqualTo("www.example.com");
        assertThat(url.port()).isEqualTo(443);
        assertThat(url.https()).isTrue();
        assertThat(url.addresses()).hasSize(1);
        assertThat(url.hostHeader()).isEqualTo("www.example.com");
    }

    @Test
    void keepsNonDefaultAllowedPort() {
        ValidatedUrl url = validator.validate("http://www.example.com:8080");
        assertThat(url.uri().toString()).isEqualTo("http://www.example.com:8080/");
        assertThat(url.hostHeader()).isEqualTo("www.example.com:8080");
    }

    @Test
    void acceptsPublicIpv6Host() {
        assertThat(validator.validate("https://v6.example.com/").addresses().get(0).getHostAddress()).contains(":");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "ftp://www.example.com/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "gopher://www.example.com/",
            "//www.example.com/",
            "www.example.com"})
    void rejectsNonHttpSchemes(String url) {
        assertThatThrownBy(() -> validator.validate(url)).isInstanceOf(UnsafeTargetException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://localhost/",
            "http://LOCALHOST:8080/",
            "http://app.localhost/",
            "http://printer.local/",
            "http://db.internal/",
            "http://intranet/",
            "http://router.home.arpa/"})
    void rejectsLocalAndInternalHostnames(String url) {
        assertThatThrownBy(() -> validator.validate(url)).isInstanceOf(UnsafeTargetException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://127.0.0.1/",
            "http://127.1.2.3/",
            "http://0.0.0.0/",
            "http://10.1.2.3/",
            "http://172.16.0.1/",
            "http://172.31.255.255/",
            "http://192.168.0.10/",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1/",
            "http://100.100.100.200/",
            "http://168.63.129.16/",
            "http://224.0.0.1/",
            "http://240.0.0.1/",
            "http://255.255.255.255/",
            "http://192.0.2.1/",
            "http://198.18.0.1/",
            "http://[::1]/",
            "http://[::]/",
            "http://[fe80::1]/",
            "http://[fd00::1]/",
            "http://[fc00::5]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:10.0.0.1]/",
            "http://[64:ff9b::a00:1]/",
            "http://[ff02::1]/"})
    void rejectsLoopbackPrivateLinkLocalMulticastReservedAndMetadataAddresses(String url) {
        assertThatThrownBy(() -> validator.validate(url))
                .isInstanceOf(UnsafeTargetException.class)
                .hasMessageContaining("not allowed");
    }

    @Test
    void rejectsHostnameResolvingToPrivateAddress() {
        assertThatThrownBy(() -> validator.validate("https://private.example.com/"))
                .isInstanceOf(UnsafeTargetException.class);
        assertThatThrownBy(() -> validator.validate("https://metadata.example.com/"))
                .isInstanceOf(UnsafeTargetException.class);
        assertThatThrownBy(() -> validator.validate("https://ula.example.com/"))
                .isInstanceOf(UnsafeTargetException.class);
    }

    @Test
    void rejectsWhenAnyResolvedAddressIsInternal() {
        // DNS answers containing one public and one loopback address (rebinding trick) are rejected.
        assertThatThrownBy(() -> validator.validate("https://rebind.example.com/"))
                .isInstanceOf(UnsafeTargetException.class);
    }

    @Test
    void rejectsUnresolvableHost() {
        assertThatThrownBy(() -> validator.validate("https://does-not-exist.example.org/"))
                .isInstanceOf(UnsafeTargetException.class)
                .hasMessageContaining("could not be resolved");
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://www.example.com:22/", "http://www.example.com:3306/", "http://www.example.com:6379/",
            "https://www.example.com:65535/"})
    void rejectsPortsOutsideAllowList(String url) {
        assertThatThrownBy(() -> validator.validate(url))
                .isInstanceOf(UnsafeTargetException.class)
                .hasMessageContaining("Port");
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://user:pass@www.example.com/", "https://www.example.com/a b", "https://www.exa\\mple.com/",
            "", "   "})
    void rejectsCredentialsWhitespaceAndMalformedInput(String url) {
        assertThatThrownBy(() -> validator.validate(url)).isInstanceOf(UnsafeTargetException.class);
    }

    @Test
    void rejectsOverlongUrl() {
        String url = "https://www.example.com/" + "a".repeat(600);
        assertThatThrownBy(() -> validator.validate(url)).isInstanceOf(UnsafeTargetException.class);
    }

    @Test
    void assertAddressAllowedRevalidatesBeforeConnecting() throws Exception {
        assertThatThrownBy(() -> validator.assertAddressAllowed(InetAddress.getByName("127.0.0.1")))
                .isInstanceOf(UnsafeTargetException.class);
        validator.assertAddressAllowed(InetAddress.getByName("93.184.216.34"));
    }
}
