package com.zerotrust.entity;

public enum MonitoringState {
    PENDING,
    BASELINE,
    STABLE,
    CHANGES_DETECTED,
    DEGRADED,
    UNAVAILABLE
}
