package com.zerotrust.security;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.zerotrust.config.ZeroTrustProperties;
import com.zerotrust.exception.UnsafeTargetException;
import com.zerotrust.util.IpAddressRules;

/**
 * SSRF protection for the scanner. Every URL - registered targets and every
 * redirect destination - must pass through {@link #validate(URI)} before any
 * network connection is made.
 */
@Component
public class TargetUrlValidator {

    private static final int MAX_URL_LENGTH = 500;

    private static final Pattern HOSTNAME = Pattern.compile(
            "^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\\.([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?))+$");

    private static final Pattern IPV4_LITERAL = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    private static final List<String> BLOCKED_HOST_SUFFIXES = List.of(
            "localhost", ".localhost", ".local", ".localdomain", ".internal", ".intranet",
            ".corp", ".home", ".lan", ".home.arpa", ".in-addr.arpa", ".ip6.arpa");

    /**
     * A URL that passed every SSRF check, together with the exact addresses that
     * were validated. Connections must be made to these addresses only, so a DNS
     * answer that changes after validation (DNS rebinding) cannot be exploited.
     */
    public record ValidatedUrl(URI uri, String host, int port, boolean https, List<InetAddress> addresses) {

        /** Value of the HTTP Host header. */
        public String hostHeader() {
            String h = host.contains(":") ? "[" + host + "]" : host;
            int defaultPort = https ? 443 : 80;
            return port == defaultPort ? h : h + ":" + port;
        }

        /** Path and query to place in the HTTP request line. */
        public String requestTarget() {
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            return uri.getRawQuery() == null ? path : path + "?" + uri.getRawQuery();
        }
    }

    private final HostResolver resolver;
    private final Set<Integer> allowedPorts;

    @Autowired
    public TargetUrlValidator(ZeroTrustProperties properties) {
        this(InetAddress::getAllByName, properties.getScanner().getAllowedPorts());
    }

    public TargetUrlValidator(HostResolver resolver, Set<Integer> allowedPorts) {
        this.resolver = resolver;
        this.allowedPorts = Set.copyOf(allowedPorts);
    }

    /**
     * Checks URL syntax, scheme, port and hostname, and returns a normalized URI.
     * Does not perform DNS resolution.
     */
    public URI normalize(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            throw new UnsafeTargetException("URL is required.");
        }
        String trimmed = rawUrl.trim();
        if (trimmed.length() > MAX_URL_LENGTH) {
            throw new UnsafeTargetException("URL must not exceed " + MAX_URL_LENGTH + " characters.");
        }
        if (trimmed.chars().anyMatch(c -> c <= 0x20 || c == 0x7f || c == '\\')) {
            throw new UnsafeTargetException("URL contains whitespace or illegal characters.");
        }
        URI uri;
        try {
            uri = new URI(trimmed);
        } catch (URISyntaxException e) {
            throw new UnsafeTargetException("URL is not valid.");
        }
        return normalize(uri);
    }

    private URI normalize(URI uri) {
        String scheme = uri.getScheme() == null ? null : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw new UnsafeTargetException("Only http:// and https:// URLs are allowed.");
        }
        if (uri.isOpaque() || uri.getRawAuthority() == null) {
            throw new UnsafeTargetException("URL must contain a hostname.");
        }
        if (uri.getRawUserInfo() != null) {
            throw new UnsafeTargetException("URLs with embedded credentials are not allowed.");
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new UnsafeTargetException("URL hostname is missing or invalid.");
        }
        host = stripBrackets(host.toLowerCase(Locale.ROOT));
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        validateHostname(host);

        boolean https = "https".equals(scheme);
        int port = uri.getPort() == -1 ? (https ? 443 : 80) : uri.getPort();
        if (!allowedPorts.contains(port)) {
            throw new UnsafeTargetException("Port " + port + " is not allowed. Allowed ports: " + allowedPorts + ".");
        }

        StringBuilder sb = new StringBuilder(scheme).append("://")
                .append(host.contains(":") ? "[" + host + "]" : host);
        if (port != (https ? 443 : 80)) {
            sb.append(':').append(port);
        }
        String path = uri.getRawPath();
        sb.append(path == null || path.isEmpty() ? "/" : path);
        if (uri.getRawQuery() != null) {
            sb.append('?').append(uri.getRawQuery());
        }
        return URI.create(sb.toString());
    }

    private void validateHostname(String host) {
        if (isIpLiteral(host)) {
            return; // the address itself is checked after "resolution"
        }
        for (String suffix : BLOCKED_HOST_SUFFIXES) {
            if (host.equals(suffix) || host.endsWith(suffix) && suffix.startsWith(".")) {
                throw new UnsafeTargetException("Internal or local hostnames are not allowed.");
            }
        }
        if (!host.contains(".")) {
            throw new UnsafeTargetException("Single-label hostnames are not allowed; use a public domain name.");
        }
        if (!HOSTNAME.matcher(host).matches()) {
            throw new UnsafeTargetException("Hostname is not a valid domain name.");
        }
    }

    /** Full validation: syntax checks plus DNS resolution and IP range checks. */
    public ValidatedUrl validate(String rawUrl) {
        return validate(normalize(rawUrl));
    }

    /** Full validation of an already-parsed URI, e.g. a redirect destination. */
    public ValidatedUrl validate(URI candidate) {
        URI uri = normalize(candidate);
        String host = stripBrackets(uri.getHost());
        boolean https = "https".equals(uri.getScheme());
        int port = uri.getPort() == -1 ? (https ? 443 : 80) : uri.getPort();

        InetAddress[] resolved;
        try {
            // IP literals are parsed directly and never passed to DNS, so the literal itself is what gets checked.
            resolved = isIpLiteral(host)
                    ? new InetAddress[] {InetAddress.getByName(host)}
                    : resolver.resolve(host);
        } catch (UnknownHostException e) {
            throw new UnsafeTargetException("Hostname '" + host + "' could not be resolved.");
        }
        if (resolved == null || resolved.length == 0) {
            throw new UnsafeTargetException("Hostname '" + host + "' did not resolve to any address.");
        }
        // Every address must be public: a single private answer rejects the target.
        for (InetAddress address : resolved) {
            assertAddressAllowed(address);
        }
        return new ValidatedUrl(uri, host, port, https, List.of(resolved));
    }

    /** Re-checks an address immediately before a connection is opened. */
    public void assertAddressAllowed(InetAddress address) {
        if (isBlockedAddress(address)) {
            throw new UnsafeTargetException(
                    "Destination resolves to a private, internal or reserved address, which is not allowed.");
        }
    }

    protected boolean isBlockedAddress(InetAddress address) {
        return IpAddressRules.isBlocked(address);
    }

    public Set<Integer> getAllowedPorts() {
        return allowedPorts;
    }

    private static boolean isIpLiteral(String host) {
        return host.contains(":") || IPV4_LITERAL.matcher(host).matches();
    }

    private static String stripBrackets(String host) {
        if (host.startsWith("[") && host.endsWith("]")) {
            return host.substring(1, host.length() - 1);
        }
        return host;
    }
}
