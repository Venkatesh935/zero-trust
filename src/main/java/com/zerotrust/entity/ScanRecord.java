package com.zerotrust.entity;

import java.time.Instant;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.DocumentReference;

/**
 * One passive security assessment of a website target. Only metadata needed
 * for the assessment is stored: no page bodies and no cookie values.
 */
@Document("scan_records")
@CompoundIndex(name = "idx_scans_target_started", def = "{'target': 1, 'startedAt': -1}")
public class ScanRecord extends LongIdEntity {

    @DocumentReference
    private WebsiteTarget target;

    /** Null for scheduled scans run by the monitoring system. */
    @DocumentReference
    private AppUser initiatedBy;

    private ScanTrigger trigger;

    @Indexed
    private ScanStatus status;

    @Indexed
    private Instant startedAt;

    private Instant completedAt;

    private String scannedUrl;

    // ---- HTTP response metadata ----
    private String finalUrl;

    private Integer httpStatusCode;

    private Long responseTimeMs;

    private String contentType;

    private String redirectChain;

    private Integer redirectCount;

    // ---- HTTPS ----
    private Boolean httpsAvailable;

    private Boolean httpAvailable;

    private Boolean httpRedirectsToHttps;

    // ---- TLS certificate ----
    private String tlsProtocol;

    private String tlsCipherSuite;

    private String tlsSubject;

    private String tlsIssuer;

    private Instant tlsValidFrom;

    private Instant tlsValidTo;

    private Long tlsDaysRemaining;

    private Boolean tlsTrusted;

    private String tlsError;

    // ---- Risk result ----
    private Integer score;

    private RiskLevel riskLevel;

    private int totalFindings;

    private int criticalCount;

    private int highCount;

    private int mediumCount;

    private int lowCount;

    private int infoCount;

    private String errorMessage;

    public WebsiteTarget getTarget() {
        return target;
    }

    public void setTarget(WebsiteTarget target) {
        this.target = target;
    }

    public AppUser getInitiatedBy() {
        return initiatedBy;
    }

    public void setInitiatedBy(AppUser initiatedBy) {
        this.initiatedBy = initiatedBy;
    }

    public ScanTrigger getTrigger() {
        return trigger;
    }

    public void setTrigger(ScanTrigger trigger) {
        this.trigger = trigger;
    }

    public ScanStatus getStatus() {
        return status;
    }

    public void setStatus(ScanStatus status) {
        this.status = status;
    }

    public Instant getStartedAt() {
        return startedAt;
    }

    public void setStartedAt(Instant startedAt) {
        this.startedAt = startedAt;
    }

    public Instant getCompletedAt() {
        return completedAt;
    }

    public void setCompletedAt(Instant completedAt) {
        this.completedAt = completedAt;
    }

    public String getScannedUrl() {
        return scannedUrl;
    }

    public void setScannedUrl(String scannedUrl) {
        this.scannedUrl = scannedUrl;
    }

    public String getFinalUrl() {
        return finalUrl;
    }

    public void setFinalUrl(String finalUrl) {
        this.finalUrl = finalUrl;
    }

    public Integer getHttpStatusCode() {
        return httpStatusCode;
    }

    public void setHttpStatusCode(Integer httpStatusCode) {
        this.httpStatusCode = httpStatusCode;
    }

    public Long getResponseTimeMs() {
        return responseTimeMs;
    }

    public void setResponseTimeMs(Long responseTimeMs) {
        this.responseTimeMs = responseTimeMs;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getRedirectChain() {
        return redirectChain;
    }

    public void setRedirectChain(String redirectChain) {
        this.redirectChain = redirectChain;
    }

    public Integer getRedirectCount() {
        return redirectCount;
    }

    public void setRedirectCount(Integer redirectCount) {
        this.redirectCount = redirectCount;
    }

    public Boolean getHttpsAvailable() {
        return httpsAvailable;
    }

    public void setHttpsAvailable(Boolean httpsAvailable) {
        this.httpsAvailable = httpsAvailable;
    }

    public Boolean getHttpAvailable() {
        return httpAvailable;
    }

    public void setHttpAvailable(Boolean httpAvailable) {
        this.httpAvailable = httpAvailable;
    }

    public Boolean getHttpRedirectsToHttps() {
        return httpRedirectsToHttps;
    }

    public void setHttpRedirectsToHttps(Boolean httpRedirectsToHttps) {
        this.httpRedirectsToHttps = httpRedirectsToHttps;
    }

    public String getTlsProtocol() {
        return tlsProtocol;
    }

    public void setTlsProtocol(String tlsProtocol) {
        this.tlsProtocol = tlsProtocol;
    }

    public String getTlsCipherSuite() {
        return tlsCipherSuite;
    }

    public void setTlsCipherSuite(String tlsCipherSuite) {
        this.tlsCipherSuite = tlsCipherSuite;
    }

    public String getTlsSubject() {
        return tlsSubject;
    }

    public void setTlsSubject(String tlsSubject) {
        this.tlsSubject = tlsSubject;
    }

    public String getTlsIssuer() {
        return tlsIssuer;
    }

    public void setTlsIssuer(String tlsIssuer) {
        this.tlsIssuer = tlsIssuer;
    }

    public Instant getTlsValidFrom() {
        return tlsValidFrom;
    }

    public void setTlsValidFrom(Instant tlsValidFrom) {
        this.tlsValidFrom = tlsValidFrom;
    }

    public Instant getTlsValidTo() {
        return tlsValidTo;
    }

    public void setTlsValidTo(Instant tlsValidTo) {
        this.tlsValidTo = tlsValidTo;
    }

    public Long getTlsDaysRemaining() {
        return tlsDaysRemaining;
    }

    public void setTlsDaysRemaining(Long tlsDaysRemaining) {
        this.tlsDaysRemaining = tlsDaysRemaining;
    }

    public Boolean getTlsTrusted() {
        return tlsTrusted;
    }

    public void setTlsTrusted(Boolean tlsTrusted) {
        this.tlsTrusted = tlsTrusted;
    }

    public String getTlsError() {
        return tlsError;
    }

    public void setTlsError(String tlsError) {
        this.tlsError = tlsError;
    }

    public Integer getScore() {
        return score;
    }

    public void setScore(Integer score) {
        this.score = score;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(RiskLevel riskLevel) {
        this.riskLevel = riskLevel;
    }

    public int getTotalFindings() {
        return totalFindings;
    }

    public void setTotalFindings(int totalFindings) {
        this.totalFindings = totalFindings;
    }

    public int getCriticalCount() {
        return criticalCount;
    }

    public void setCriticalCount(int criticalCount) {
        this.criticalCount = criticalCount;
    }

    public int getHighCount() {
        return highCount;
    }

    public void setHighCount(int highCount) {
        this.highCount = highCount;
    }

    public int getMediumCount() {
        return mediumCount;
    }

    public void setMediumCount(int mediumCount) {
        this.mediumCount = mediumCount;
    }

    public int getLowCount() {
        return lowCount;
    }

    public void setLowCount(int lowCount) {
        this.lowCount = lowCount;
    }

    public int getInfoCount() {
        return infoCount;
    }

    public void setInfoCount(int infoCount) {
        this.infoCount = infoCount;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}
