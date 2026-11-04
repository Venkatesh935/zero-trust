package com.zerotrust.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

/**
 * Decides whether an IP address is a forbidden scan destination (SSRF protection).
 * Blocks loopback, private, link-local, multicast, reserved, documentation,
 * carrier-grade NAT, IPv6 transition ranges and well-known cloud metadata endpoints.
 */
public final class IpAddressRules {

    private static final List<Cidr> BLOCKED_IPV4 = parse(
            "0.0.0.0/8",          // "this" network
            "10.0.0.0/8",         // private
            "100.64.0.0/10",      // carrier-grade NAT (includes 100.100.100.200 Alibaba metadata)
            "127.0.0.0/8",        // loopback
            "169.254.0.0/16",     // link-local (includes 169.254.169.254 cloud metadata)
            "172.16.0.0/12",      // private
            "192.0.0.0/24",       // IETF protocol assignments (includes 192.0.0.192 Oracle metadata)
            "192.0.2.0/24",       // documentation TEST-NET-1
            "192.88.99.0/24",     // 6to4 relay anycast
            "192.168.0.0/16",     // private
            "198.18.0.0/15",      // benchmarking
            "198.51.100.0/24",    // documentation TEST-NET-2
            "203.0.113.0/24",     // documentation TEST-NET-3
            "224.0.0.0/4",        // multicast
            "240.0.0.0/4",        // reserved
            "255.255.255.255/32", // broadcast
            "168.63.129.16/32"    // Azure platform/metadata endpoint (public range, blocked explicitly)
    );

    private static final List<Cidr> BLOCKED_IPV6 = parse(
            "::/128",             // unspecified
            "::1/128",            // loopback
            "64:ff9b::/96",       // NAT64 (could reach internal IPv4)
            "64:ff9b:1::/48",     // local-use NAT64
            "100::/64",           // discard-only
            "2001::/32",          // Teredo tunnelling
            "2001:db8::/32",      // documentation
            "2002::/16",          // 6to4 (embeds arbitrary IPv4)
            "fc00::/7",           // unique local (includes fd00:ec2::254 AWS metadata)
            "fe80::/10",          // link-local
            "fec0::/10",          // deprecated site-local
            "ff00::/8"            // multicast
    );

    private IpAddressRules() {
    }

    public static boolean isBlocked(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (bytes.length == 16) {
            byte[] embedded = embeddedIpv4(bytes);
            if (embedded != null) {
                return matchesAny(BLOCKED_IPV4, embedded);
            }
            return matchesAny(BLOCKED_IPV6, bytes);
        }
        return matchesAny(BLOCKED_IPV4, bytes);
    }

    /** Returns the IPv4 part of an IPv4-mapped (::ffff:a.b.c.d) or IPv4-compatible (::a.b.c.d) address. */
    private static byte[] embeddedIpv4(byte[] v6) {
        for (int i = 0; i < 10; i++) {
            if (v6[i] != 0) {
                return null;
            }
        }
        boolean mapped = (v6[10] & 0xff) == 0xff && (v6[11] & 0xff) == 0xff;
        boolean compatible = v6[10] == 0 && v6[11] == 0;
        if (!mapped && !compatible) {
            return null;
        }
        if (compatible && v6[12] == 0 && v6[13] == 0 && v6[14] == 0 && (v6[15] == 0 || v6[15] == 1)) {
            return null; // :: and ::1 are handled by the IPv6 list
        }
        return Arrays.copyOfRange(v6, 12, 16);
    }

    private static boolean matchesAny(List<Cidr> ranges, byte[] address) {
        for (Cidr cidr : ranges) {
            if (cidr.contains(address)) {
                return true;
            }
        }
        return false;
    }

    private static List<Cidr> parse(String... cidrs) {
        return Arrays.stream(cidrs).map(Cidr::parse).toList();
    }

    private record Cidr(byte[] network, int prefixLength) {

        static Cidr parse(String text) {
            String[] parts = text.split("/");
            try {
                // Only IP literals are passed here, so no DNS lookup takes place.
                byte[] network = InetAddress.getByName(parts[0]).getAddress();
                return new Cidr(network, Integer.parseInt(parts[1]));
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("Invalid CIDR " + text, e);
            }
        }

        boolean contains(byte[] address) {
            if (address.length != network.length) {
                return false;
            }
            int fullBytes = prefixLength / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (address[i] != network[i]) {
                    return false;
                }
            }
            int remainingBits = prefixLength % 8;
            if (remainingBits == 0) {
                return true;
            }
            int mask = (0xff << (8 - remainingBits)) & 0xff;
            return (address[fullBytes] & mask) == (network[fullBytes] & mask);
        }
    }
}
