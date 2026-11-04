package com.zerotrust.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.zerotrust.entity.FindingCategory;
import com.zerotrust.entity.RiskLevel;
import com.zerotrust.entity.Severity;
import com.zerotrust.service.RiskScoringService.RiskResult;
import com.zerotrust.service.scanner.FindingDraft;

class RiskScoringServiceTest {

    private final RiskScoringService scoring = new RiskScoringService();

    private static FindingDraft fail(FindingCategory c, Severity s) {
        return FindingDraft.fail(c, c + "_" + s + "_" + Math.random(), s, "t", "d", "e", "r");
    }

    @Test
    void noFailedChecksScores100Excellent() {
        RiskResult r = scoring.calculate(List.of(FindingDraft.pass(FindingCategory.HTTPS, "A", "t", "d", "e")));
        assertThat(r.score()).isEqualTo(100);
        assertThat(r.riskLevel()).isEqualTo(RiskLevel.EXCELLENT);
        assertThat(r.totalFindings()).isZero();
    }

    @Test
    void deductionsFollowSeverityWeights() {
        RiskResult r = scoring.calculate(List.of(
                fail(FindingCategory.SECURITY_HEADERS, Severity.HIGH),      // 15
                fail(FindingCategory.SECURITY_HEADERS, Severity.MEDIUM),    // 8
                fail(FindingCategory.COOKIES, Severity.LOW),                // 3
                fail(FindingCategory.INFORMATION_DISCLOSURE, Severity.INFORMATIONAL))); // 0
        assertThat(r.score()).isEqualTo(100 - 15 - 8 - 3);
        assertThat(r.riskLevel()).isEqualTo(RiskLevel.MODERATE); // 74
        assertThat(r.totalFindings()).isEqualTo(4);
        assertThat(r.count(Severity.INFORMATIONAL)).isEqualTo(1);
    }

    @Test
    void categoryDeductionIsCapped() {
        List<FindingDraft> many = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            many.add(fail(FindingCategory.COOKIES, Severity.MEDIUM)); // 80 raw, capped at 15
        }
        RiskResult r = scoring.calculate(many);
        assertThat(r.score()).isEqualTo(85);
        assertThat(r.categories()).filteredOn(c -> c.category() == FindingCategory.COOKIES)
                .singleElement().satisfies(c -> {
                    assertThat(c.rawDeduction()).isEqualTo(80);
                    assertThat(c.appliedDeduction()).isEqualTo(15);
                });
    }

    @Test
    void criticalFindingCapsScoreAt49() {
        RiskResult r = scoring.calculate(List.of(fail(FindingCategory.TLS, Severity.CRITICAL)));
        assertThat(r.score()).isEqualTo(RiskScoringService.CRITICAL_CEILING);
        assertThat(r.criticalCeilingApplied()).isTrue();
        assertThat(r.riskLevel()).isEqualTo(RiskLevel.HIGH_RISK);
    }

    @Test
    void scoreNeverDropsBelowZero() {
        List<FindingDraft> list = new ArrayList<>();
        for (FindingCategory c : FindingCategory.values()) {
            for (int i = 0; i < 5; i++) {
                list.add(fail(c, Severity.CRITICAL));
            }
        }
        RiskResult r = scoring.calculate(list);
        assertThat(r.score()).isBetween(0, 24);
        assertThat(r.riskLevel()).isEqualTo(RiskLevel.CRITICAL_RISK);
    }

    @Test
    void classificationBoundaries() {
        assertThat(RiskLevel.fromScore(100)).isEqualTo(RiskLevel.EXCELLENT);
        assertThat(RiskLevel.fromScore(90)).isEqualTo(RiskLevel.EXCELLENT);
        assertThat(RiskLevel.fromScore(89)).isEqualTo(RiskLevel.GOOD);
        assertThat(RiskLevel.fromScore(75)).isEqualTo(RiskLevel.GOOD);
        assertThat(RiskLevel.fromScore(74)).isEqualTo(RiskLevel.MODERATE);
        assertThat(RiskLevel.fromScore(50)).isEqualTo(RiskLevel.MODERATE);
        assertThat(RiskLevel.fromScore(49)).isEqualTo(RiskLevel.HIGH_RISK);
        assertThat(RiskLevel.fromScore(25)).isEqualTo(RiskLevel.HIGH_RISK);
        assertThat(RiskLevel.fromScore(24)).isEqualTo(RiskLevel.CRITICAL_RISK);
        assertThat(RiskLevel.fromScore(0)).isEqualTo(RiskLevel.CRITICAL_RISK);
    }
}
