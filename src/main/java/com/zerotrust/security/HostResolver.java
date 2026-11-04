package com.zerotrust.security;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Resolves a hostname to IP addresses. Abstracted so that tests can simulate
 * DNS answers (including malicious ones) without network access.
 */
@FunctionalInterface
public interface HostResolver {

    InetAddress[] resolve(String host) throws UnknownHostException;
}
