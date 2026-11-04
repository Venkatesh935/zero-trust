package com.zerotrust.entity;

public enum RiskLevel {
    EXCELLENT("Excellent", 90),
    GOOD("Good", 75),
    MODERATE("Moderate", 50),
    HIGH_RISK("High Risk", 25),
    CRITICAL_RISK("Critical Risk", 0);

    private final String label;
    private final int minScore;

    RiskLevel(String label, int minScore) {
        this.label = label;
        this.minScore = minScore;
    }

    public String getLabel() {
        return label;
    }

    public int getMinScore() {
        return minScore;
    }

    public static RiskLevel fromScore(int score) {
        for (RiskLevel level : values()) {
            if (score >= level.minScore) {
                return level;
            }
        }
        return CRITICAL_RISK;
    }
}
