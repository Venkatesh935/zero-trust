package com.zerotrust.entity;

/**
 * Security check categories. Each category has a maximum score deduction
 * so that many small issues in one area cannot dominate the overall score.
 */
public enum FindingCategory {
    AVAILABILITY("Availability", 0),
    HTTPS("HTTPS Transport", 35),
    TLS("TLS Certificate", 30),
    SECURITY_HEADERS("Security Headers", 35),
    COOKIES("Cookie Security", 15),
    HTTP_RESPONSE("HTTP Response", 10),
    INFORMATION_DISCLOSURE("Information Disclosure", 6);

    private final String label;
    private final int maxDeduction;

    FindingCategory(String label, int maxDeduction) {
        this.label = label;
        this.maxDeduction = maxDeduction;
    }

    public String getLabel() {
        return label;
    }

    public int getMaxDeduction() {
        return maxDeduction;
    }
}
