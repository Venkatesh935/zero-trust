package com.zerotrust.entity;

/**
 * Minimal view of a finding needed by the risk scoring engine. Implemented by
 * both persisted findings and the in-memory drafts produced by the scanner.
 */
public interface ScorableFinding {

    FindingCategory getCategory();

    Severity getSeverity();

    boolean isPassed();

    String getCheckKey();

    String getTitle();
}
