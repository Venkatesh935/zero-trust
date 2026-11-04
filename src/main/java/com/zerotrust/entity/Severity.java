package com.zerotrust.entity;

/**
 * Severity of a security finding. The deduction is used by the risk
 * scoring engine; informational findings never reduce the score.
 */
public enum Severity {
    CRITICAL(25),
    HIGH(15),
    MEDIUM(8),
    LOW(3),
    INFORMATIONAL(0);

    private final int deduction;

    Severity(int deduction) {
        this.deduction = deduction;
    }

    public int getDeduction() {
        return deduction;
    }

    /** True when this severity is the same as or more severe than {@code other}. */
    public boolean isAtLeast(Severity other) {
        return ordinal() <= other.ordinal();
    }
}
