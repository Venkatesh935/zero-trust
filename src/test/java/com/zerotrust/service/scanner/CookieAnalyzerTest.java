package com.zerotrust.service.scanner;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.zerotrust.entity.Severity;

class CookieAnalyzerTest {

    private final CookieAnalyzer analyzer = new CookieAnalyzer();

    @Test
    void parsesAttributesCaseInsensitively() {
        CookieAnalyzer.CookieAttributes c = CookieAnalyzer.parse("sid=abc123; path=/; SECURE; httponly; samesite=Strict");
        assertThat(c.name()).isEqualTo("sid");
        assertThat(c.secure()).isTrue();
        assertThat(c.httpOnly()).isTrue();
        assertThat(c.sameSite()).isEqualTo("Strict");
    }

    @Test
    void secureCookiePasses() {
        List<FindingDraft> r = analyzer.analyze(List.of("sid=x; Secure; HttpOnly; SameSite=Lax"), true);
        assertThat(r).hasSize(1);
        assertThat(r.get(0).passed()).isTrue();
    }

    @Test
    void missingAttributesAreReported() {
        List<FindingDraft> r = analyzer.analyze(List.of("tracking=xyz; Path=/"), true);
        FindingDraft f = r.get(0);
        assertThat(f.passed()).isFalse();
        assertThat(f.severity()).isEqualTo(Severity.MEDIUM); // missing Secure on an HTTPS site
        assertThat(f.description()).contains("Secure").contains("HttpOnly").contains("SameSite");
    }

    @Test
    void sameSiteNoneWithoutSecureIsMedium() {
        FindingDraft f = analyzer.analyze(List.of("a=1; HttpOnly; SameSite=None"), false).get(0);
        assertThat(f.severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    void cookieValuesAreNeverIncludedInFindings() {
        String secret = "SuperSecretSessionToken123";
        List<FindingDraft> r = analyzer.analyze(List.of("JSESSIONID=" + secret + "; Path=/",
                "ok=" + secret + "; Secure; HttpOnly; SameSite=Strict"), true);
        assertThat(r).isNotEmpty();
        for (FindingDraft f : r) {
            assertThat(String.valueOf(f.title()) + f.description() + f.evidence() + f.recommendation())
                    .doesNotContain(secret);
        }
    }

    @Test
    void noCookiesIsAPass() {
        List<FindingDraft> r = analyzer.analyze(List.of(), true);
        assertThat(r).singleElement().matches(FindingDraft::passed);
    }

    @Test
    void ignoresBlankAndNamelessHeaders() {
        assertThat(CookieAnalyzer.parse("   ")).isNull();
        assertThat(CookieAnalyzer.parse("=value; Secure")).isNull();
    }
}
