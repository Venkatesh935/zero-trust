package com.zerotrust;

import static com.zerotrust.service.scanner.ScanFixtures.headers;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.ConnectException;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;

import com.zerotrust.entity.AuditAction;
import com.zerotrust.entity.Finding;
import com.zerotrust.entity.ScanRecord;
import com.zerotrust.entity.ScanStatus;
import com.zerotrust.entity.WebsiteTarget;
import com.zerotrust.repository.AuditLogRepository;
import com.zerotrust.repository.FindingRepository;
import com.zerotrust.repository.ScanRecordRepository;
import com.zerotrust.repository.WebsiteTargetRepository;
import com.zerotrust.security.TargetUrlValidator.ValidatedUrl;
import com.zerotrust.service.scanner.FetchResult;
import com.zerotrust.service.scanner.ResponseHeaders;
import com.zerotrust.service.scanner.ScanFixtures;

import tools.jackson.databind.json.JsonMapper;

/**
 * Register website -> scan -> results persisted -> dashboard -> report -> monitoring -> audit.
 */
class ScanWorkflowIntegrationTest extends IntegrationTestSupport {

    private static final String JSON = MediaType.APPLICATION_JSON_VALUE;

    @Autowired
    private ScanRecordRepository scans;
    @Autowired
    private FindingRepository findings;
    @Autowired
    private WebsiteTargetRepository targets;
    @Autowired
    private AuditLogRepository auditLogs;

    /** Headers returned by the mocked website; tests change them to simulate configuration changes. */
    private final AtomicReference<ResponseHeaders> siteHeaders = new AtomicReference<>();

    @BeforeEach
    void mockWebsite() throws Exception {
        siteHeaders.set(headers("Content-Type", "text/html", "Server", "nginx/1.18.0",
                "Set-Cookie", "SID=topsecretvalue; Path=/; HttpOnly"));
        when(httpFetcher.fetch(any())).thenAnswer(inv -> {
            ValidatedUrl target = inv.getArgument(0);
            String url = target.uri().toString();
            if (target.host().startsWith("down.")) {
                throw new ConnectException("Connection refused");
            }
            if (target.https()) {
                return new FetchResult(target.uri(), 200, siteHeaders.get(), 80, ScanFixtures.validTls(Instant.now(), 120));
            }
            return new FetchResult(target.uri(), 301, headers("Location", url.replace("http://", "https://")), 40, null);
        });
    }

    private long registerWebsite(MockHttpSession admin, String host) throws Exception {
        String body = mvc.perform(post("/api/websites").session(admin).with(xsrf()).contentType(JSON)
                        .content("{\"name\":\"" + host + "\",\"url\":\"https://" + host + "\",\"description\":\"test\",\"authorizationConfirmed\":true}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return JsonMapper.builder().build().readTree(body).get("data").get("id").asLong();
    }

    private long scan(MockHttpSession session, long websiteId) throws Exception {
        String body = mvc.perform(post("/api/scans").session(session).with(xsrf()).contentType(JSON)
                        .content("{\"websiteId\":" + websiteId + "}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return JsonMapper.builder().build().readTree(body).get("data").get("summary").get("id").asLong();
    }

    @Test
    void scanResultsArePersistedAndExposedThroughTheApi() throws Exception {
        MockHttpSession admin = loginAdmin();
        long websiteId = registerWebsite(admin, "shop.example.com");

        long scanId = scan(admin, websiteId);

        ScanRecord record = scans.findById(scanId).orElseThrow();
        assertThat(record.getStatus()).isEqualTo(ScanStatus.COMPLETED);
        assertThat(record.getHttpsAvailable()).isTrue();
        assertThat(record.getHttpRedirectsToHttps()).isTrue();
        assertThat(record.getTlsDaysRemaining()).isEqualTo(120);
        assertThat(record.getScore()).isNotNull().isLessThan(100);
        assertThat(record.getTotalFindings()).isPositive();

        List<Finding> stored = findings.findByScanIdOrderByIdAsc(scanId);
        assertThat(stored).extracting(Finding::getCheckKey)
                .contains("HTTPS_AVAILABLE", "HEADER_HSTS", "HEADER_CSP", "TLS_EXPIRY", "COOKIE_SID", "DISCLOSURE_SERVER");
        // Cookie values must never be persisted
        assertThat(stored).allSatisfy(f -> assertThat(f.getEvidence() + f.getDescription()).doesNotContain("topsecretvalue"));

        WebsiteTarget target = targets.findById(websiteId).orElseThrow();
        assertThat(target.getLastScanId()).isEqualTo(scanId);
        assertThat(target.getLastScore()).isEqualTo(record.getScore());

        mvc.perform(get("/api/scans/" + scanId).session(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.summary.status").value("COMPLETED"))
                .andExpect(jsonPath("$.data.risk.score").value(record.getScore()))
                .andExpect(jsonPath("$.data.risk.categories").isArray())
                .andExpect(jsonPath("$.data.tls.trusted").value(true));
        mvc.perform(get("/api/scans/" + scanId + "/findings").session(admin)).andExpect(status().isOk());
        mvc.perform(get("/api/scans?websiteId=" + websiteId).session(admin))
                .andExpect(jsonPath("$.data.totalElements").value(1));
        mvc.perform(get("/api/findings?websiteId=" + websiteId + "&severity=HIGH").session(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content[0].severity").value("HIGH"));
        mvc.perform(get("/api/dashboard/summary").session(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.totalWebsites").isNumber());
        mvc.perform(get("/api/dashboard/risk-distribution").session(admin)).andExpect(status().isOk());

        assertThat(auditLogs.findAll()).anyMatch(a -> a.getAction() == AuditAction.SCAN_COMPLETED && Long.valueOf(websiteId).equals(a.getTargetId()));
    }

    @Test
    void pdfReportIsGeneratedFromStoredScan() throws Exception {
        MockHttpSession admin = loginAdmin();
        long scanId = scan(admin, registerWebsite(admin, "report.example.com"));

        byte[] pdf = mvc.perform(get("/api/reports/" + scanId + "/pdf").session(admin))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF))
                .andExpect(header().string("Content-Disposition", org.hamcrest.Matchers.containsString(".pdf")))
                .andReturn().getResponse().getContentAsByteArray();
        assertThat(new String(pdf, 0, 5)).isEqualTo("%PDF-");
        assertThat(pdf.length).isGreaterThan(2000);
        assertThat(auditLogs.findAll()).anyMatch(a -> a.getAction() == AuditAction.REPORT_GENERATED);
    }

    @Test
    void unreachableWebsiteProducesFailedScan() throws Exception {
        MockHttpSession admin = loginAdmin();
        long scanId = scan(admin, registerWebsite(admin, "down.example.com"));
        ScanRecord record = scans.findById(scanId).orElseThrow();
        assertThat(record.getStatus()).isEqualTo(ScanStatus.FAILED);
        assertThat(record.getErrorMessage()).contains("could not be reached");
        assertThat(record.getScore()).isNull();
    }

    @Test
    void monitoringDetectsHeaderChangesAndKeepsHistory() throws Exception {
        MockHttpSession admin = loginAdmin();
        long websiteId = registerWebsite(admin, "monitored.example.com");

        // intervals below the minimum are rejected to avoid excessive requests
        mvc.perform(post("/api/monitoring").session(admin).with(xsrf()).contentType(JSON)
                .content("{\"websiteId\":" + websiteId + ",\"intervalMinutes\":1}")).andExpect(status().isBadRequest());

        String created = mvc.perform(post("/api/monitoring").session(admin).with(xsrf()).contentType(JSON)
                        .content("{\"websiteId\":" + websiteId + ",\"intervalMinutes\":30}"))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        long configId = JsonMapper.builder().build().readTree(created).get("data").get("id").asLong();

        // only one monitoring configuration per website
        mvc.perform(post("/api/monitoring").session(admin).with(xsrf()).contentType(JSON)
                .content("{\"websiteId\":" + websiteId + ",\"intervalMinutes\":60}")).andExpect(status().isConflict());

        mvc.perform(post("/api/monitoring/" + configId + "/run").session(admin).with(xsrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.state").value("BASELINE"));

        // The website adds HSTS and CSP: the next check reports the change and a higher score.
        siteHeaders.set(headers("Content-Type", "text/html", "Server", "nginx/1.18.0",
                "Strict-Transport-Security", "max-age=31536000", "Content-Security-Policy", "default-src 'self'",
                "Set-Cookie", "SID=topsecretvalue; Path=/; HttpOnly"));
        mvc.perform(post("/api/monitoring/" + configId + "/run").session(admin).with(xsrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.state").value("CHANGES_DETECTED"))
                .andExpect(jsonPath("$.data.scoreChange").value(org.hamcrest.Matchers.greaterThan(0)))
                .andExpect(jsonPath("$.data.changes[?(@ =~ /Resolved: Strict-Transport-Security.*/)]").exists());

        mvc.perform(get("/api/monitoring/" + configId + "/history").session(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.totalElements").value(2));

        mvc.perform(put("/api/monitoring/" + configId).session(admin).with(xsrf()).contentType(JSON)
                .content("{\"enabled\":false}")).andExpect(jsonPath("$.data.enabled").value(false));
        mvc.perform(delete("/api/monitoring/" + configId).session(admin).with(xsrf())).andExpect(status().isOk());
        assertThat(auditLogs.findAll()).anyMatch(a -> a.getAction() == AuditAction.MONITORING_DELETED);
    }

    @Test
    void deletingWebsiteRemovesItsScans() throws Exception {
        MockHttpSession admin = loginAdmin();
        long websiteId = registerWebsite(admin, "delete-me.example.com");
        long scanId = scan(admin, websiteId);
        mvc.perform(delete("/api/websites/" + websiteId).session(admin).with(xsrf())).andExpect(status().isOk());
        assertThat(scans.findById(scanId)).isEmpty();
        assertThat(findings.findByScanIdOrderByIdAsc(scanId)).isEmpty();
        assertThat(auditLogs.findAll()).anyMatch(a -> a.getAction() == AuditAction.WEBSITE_DELETED && Long.valueOf(websiteId).equals(a.getTargetId()));
    }
}
