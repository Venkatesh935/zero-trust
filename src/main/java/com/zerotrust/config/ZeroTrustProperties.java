package com.zerotrust.config;

import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Application settings bound from {@code zerotrust.*} properties.
 */
@ConfigurationProperties(prefix = "zerotrust")
public class ZeroTrustProperties {

    private final Admin admin = new Admin();
    private final Security security = new Security();
    private final Scanner scanner = new Scanner();
    private final Monitoring monitoring = new Monitoring();

    public Admin getAdmin() {
        return admin;
    }

    public Security getSecurity() {
        return security;
    }

    public Scanner getScanner() {
        return scanner;
    }

    public Monitoring getMonitoring() {
        return monitoring;
    }

    /** Initial administrator created on first start when no users exist. */
    public static class Admin {
        private String username = "admin";
        private String password = "";

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }

    public static class Security {
        private int maxFailedLogins = 5;
        private int lockoutMinutes = 15;

        public int getMaxFailedLogins() {
            return maxFailedLogins;
        }

        public void setMaxFailedLogins(int maxFailedLogins) {
            this.maxFailedLogins = maxFailedLogins;
        }

        public int getLockoutMinutes() {
            return lockoutMinutes;
        }

        public void setLockoutMinutes(int lockoutMinutes) {
            this.lockoutMinutes = lockoutMinutes;
        }
    }

    public static class Scanner {
        private int connectTimeoutMs = 5000;
        private int readTimeoutMs = 8000;
        private int maxHeaderBytes = 65536;
        private int maxRedirects = 5;
        private Set<Integer> allowedPorts = new LinkedHashSet<>(Set.of(80, 443, 8080, 8443));
        private int manualScanCooldownSeconds = 30;

        public int getConnectTimeoutMs() {
            return connectTimeoutMs;
        }

        public void setConnectTimeoutMs(int connectTimeoutMs) {
            this.connectTimeoutMs = connectTimeoutMs;
        }

        public int getReadTimeoutMs() {
            return readTimeoutMs;
        }

        public void setReadTimeoutMs(int readTimeoutMs) {
            this.readTimeoutMs = readTimeoutMs;
        }

        public int getMaxHeaderBytes() {
            return maxHeaderBytes;
        }

        public void setMaxHeaderBytes(int maxHeaderBytes) {
            this.maxHeaderBytes = maxHeaderBytes;
        }

        public int getMaxRedirects() {
            return maxRedirects;
        }

        public void setMaxRedirects(int maxRedirects) {
            this.maxRedirects = maxRedirects;
        }

        public Set<Integer> getAllowedPorts() {
            return allowedPorts;
        }

        public void setAllowedPorts(Set<Integer> allowedPorts) {
            this.allowedPorts = allowedPorts;
        }

        public int getManualScanCooldownSeconds() {
            return manualScanCooldownSeconds;
        }

        public void setManualScanCooldownSeconds(int manualScanCooldownSeconds) {
            this.manualScanCooldownSeconds = manualScanCooldownSeconds;
        }
    }

    public static class Monitoring {
        private boolean schedulerEnabled = true;
        private int minIntervalMinutes = 5;
        private int maxIntervalMinutes = 1440;
        private int maxChecksPerCycle = 3;

        public boolean isSchedulerEnabled() {
            return schedulerEnabled;
        }

        public void setSchedulerEnabled(boolean schedulerEnabled) {
            this.schedulerEnabled = schedulerEnabled;
        }

        public int getMinIntervalMinutes() {
            return minIntervalMinutes;
        }

        public void setMinIntervalMinutes(int minIntervalMinutes) {
            this.minIntervalMinutes = minIntervalMinutes;
        }

        public int getMaxIntervalMinutes() {
            return maxIntervalMinutes;
        }

        public void setMaxIntervalMinutes(int maxIntervalMinutes) {
            this.maxIntervalMinutes = maxIntervalMinutes;
        }

        public int getMaxChecksPerCycle() {
            return maxChecksPerCycle;
        }

        public void setMaxChecksPerCycle(int maxChecksPerCycle) {
            this.maxChecksPerCycle = maxChecksPerCycle;
        }
    }
}
