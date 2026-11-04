package com.zerotrust.service;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

import org.springframework.stereotype.Service;

import com.lowagie.text.Chunk;
import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.ColumnText;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfPageEventHelper;
import com.lowagie.text.pdf.PdfWriter;
import com.zerotrust.entity.AuditAction;
import com.zerotrust.entity.Finding;
import com.zerotrust.entity.FindingCategory;
import com.zerotrust.entity.ScanRecord;
import com.zerotrust.entity.ScanStatus;
import com.zerotrust.entity.Severity;
import com.zerotrust.exception.ApiException;
import com.zerotrust.repository.FindingRepository;
import com.zerotrust.repository.ScanRecordRepository;
import com.zerotrust.security.CurrentUserService;
import com.zerotrust.service.RiskScoringService.CategoryScore;
import com.zerotrust.service.RiskScoringService.RiskResult;

/**
 * Generates the downloadable PDF security assessment report from a stored scan.
 */
@Service
public class ReportService {

    public static final String PROJECT_NAME = "ZERO TRUST - Website Security Assessment and Continuous Monitoring System";

    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("dd MMM yyyy, HH:mm:ss z")
            .withZone(ZoneId.systemDefault());
    private static final Color NAVY = new Color(11, 16, 32);
    private static final Color ACCENT = new Color(14, 116, 144);
    private static final Color LIGHT = new Color(236, 242, 248);
    private static final Color BORDER = new Color(200, 210, 222);

    private static final Font TITLE = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, NAVY);
    private static final Font SUBTITLE = FontFactory.getFont(FontFactory.HELVETICA, 10, Color.DARK_GRAY);
    private static final Font H2 = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 13, ACCENT);
    private static final Font BODY = FontFactory.getFont(FontFactory.HELVETICA, 9, Color.BLACK);
    private static final Font BODY_BOLD = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9, Color.BLACK);
    private static final Font SMALL = FontFactory.getFont(FontFactory.HELVETICA, 8, Color.DARK_GRAY);
    private static final Font HEADER_CELL = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9, Color.WHITE);

    private final ScanRecordRepository scans;
    private final FindingRepository findings;
    private final RiskScoringService scoring;
    private final CurrentUserService currentUserService;
    private final AuditService auditService;

    public ReportService(ScanRecordRepository scans, FindingRepository findings, RiskScoringService scoring,
            CurrentUserService currentUserService, AuditService auditService) {
        this.scans = scans;
        this.findings = findings;
        this.scoring = scoring;
        this.currentUserService = currentUserService;
        this.auditService = auditService;
    }

    public record Report(String fileName, byte[] content) {
    }

    public Report generate(Long scanId) {
        ScanRecord scan = scans.findById(scanId).orElseThrow(() -> ApiException.notFound("Scan not found."));
        currentUserService.checkTargetAccess(scan.getTarget().getId());
        if (scan.getStatus() == ScanStatus.RUNNING) {
            throw ApiException.conflict("The scan is still running. Generate the report after it completes.");
        }
        List<Finding> list = ScanService.sortForDisplay(findings.findByScanIdOrderByIdAsc(scanId));
        byte[] pdf = render(scan, list);
        auditService.log(AuditAction.REPORT_GENERATED,
                "PDF report generated for scan #" + scanId + " (" + scan.getTarget().getName() + ")",
                scan.getTarget().getId());
        String safeName = scan.getTarget().getName().replaceAll("[^A-Za-z0-9_-]+", "_");
        return new Report("ZeroTrust_Report_" + safeName + "_scan" + scanId + ".pdf", pdf);
    }

    byte[] render(ScanRecord scan, List<Finding> list) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Document document = new Document(PageSize.A4, 40, 40, 50, 50);
        try {
            PdfWriter writer = PdfWriter.getInstance(document, out);
            writer.setPageEvent(new Footer());
            document.addTitle("Security Assessment Report - " + scan.getTarget().getName());
            document.addCreator("Zero Trust Security Assessment System");
            document.open();

            boolean completed = scan.getStatus() == ScanStatus.COMPLETED;
            RiskResult risk = completed ? scoring.calculate(list) : null;

            // 1-4: project, website and assessment details
            Paragraph title = new Paragraph("Website Security Assessment Report", TITLE);
            document.add(title);
            document.add(new Paragraph(PROJECT_NAME, SUBTITLE));
            document.add(spacer());
            PdfPTable info = keyValueTable();
            row(info, "Website name", scan.getTarget().getName());
            row(info, "Website URL", scan.getTarget().getUrl());
            row(info, "Assessment date", format(scan.getStartedAt()));
            row(info, "Scan ID / type", "#" + scan.getId() + " / " + scan.getTrigger());
            row(info, "Initiated by", scan.getInitiatedBy() != null ? scan.getInitiatedBy().getUsername() : "Monitoring scheduler");
            row(info, "Scan status", scan.getStatus().name());
            document.add(info);

            // 5-6: score and risk classification
            section(document, "1. Overall Security Score");
            if (completed) {
                PdfPTable score = new PdfPTable(new float[] {1, 2});
                score.setWidthPercentage(100);
                PdfPCell big = new PdfPCell(new Phrase(scan.getScore() + " / 100",
                        FontFactory.getFont(FontFactory.HELVETICA_BOLD, 26, scoreColor(scan.getScore()))));
                big.setHorizontalAlignment(Element.ALIGN_CENTER);
                big.setVerticalAlignment(Element.ALIGN_MIDDLE);
                big.setPadding(12);
                big.setBorderColor(BORDER);
                score.addCell(big);
                Paragraph classification = new Paragraph();
                classification.add(new Chunk("Risk classification: ", BODY_BOLD));
                classification.add(new Chunk(scan.getRiskLevel().getLabel() + "\n", BODY_BOLD));
                classification.add(new Chunk(RiskScoringService.describe(scan.getRiskLevel()) + "\n\n", BODY));
                classification.add(new Chunk("Findings: " + scan.getTotalFindings() + "  (Critical " + scan.getCriticalCount()
                        + ", High " + scan.getHighCount() + ", Medium " + scan.getMediumCount() + ", Low "
                        + scan.getLowCount() + ", Informational " + scan.getInfoCount() + ")", BODY));
                if (risk.criticalCeilingApplied()) {
                    classification.add(new Chunk("\nScore limited to " + RiskScoringService.CRITICAL_CEILING
                            + " because at least one CRITICAL finding exists.", SMALL));
                }
                PdfPCell text = new PdfPCell(classification);
                text.setPadding(10);
                text.setBorderColor(BORDER);
                score.addCell(text);
                document.add(score);

                document.add(spacer());
                PdfPTable breakdown = table(new float[] {3, 1.2f, 1.4f, 1.2f}, "Category", "Failed checks",
                        "Deduction (max)", "Applied");
                for (CategoryScore c : risk.categories()) {
                    cell(breakdown, c.label());
                    cell(breakdown, String.valueOf(c.failedChecks()));
                    cell(breakdown, c.rawDeduction() + " (" + c.maxDeduction() + ")");
                    cell(breakdown, "-" + c.appliedDeduction());
                }
                document.add(breakdown);
            } else {
                document.add(new Paragraph("The website could not be assessed, so no score was calculated. Reason: "
                        + nullSafe(scan.getErrorMessage()), BODY));
            }

            // 7: HTTPS
            section(document, "2. HTTPS Status");
            PdfPTable https = keyValueTable();
            row(https, "HTTPS available", yesNo(scan.getHttpsAvailable()));
            row(https, "Plain HTTP reachable", yesNo(scan.getHttpAvailable()));
            row(https, "HTTP redirects to HTTPS", yesNo(scan.getHttpRedirectsToHttps()));
            row(https, "Final URL", nullSafe(scan.getFinalUrl()));
            row(https, "HTTP status / response time", (scan.getHttpStatusCode() == null ? "-" : scan.getHttpStatusCode())
                    + " / " + (scan.getResponseTimeMs() == null ? "-" : scan.getResponseTimeMs() + " ms"));
            row(https, "Content type", nullSafe(scan.getContentType()));
            row(https, "Redirect chain", nullSafe(scan.getRedirectChain()));
            document.add(https);

            // 8: TLS certificate
            section(document, "3. TLS Certificate Information");
            PdfPTable tls = keyValueTable();
            row(tls, "Certificate trusted", yesNo(scan.getTlsTrusted()));
            row(tls, "Subject", nullSafe(scan.getTlsSubject()));
            row(tls, "Issuer", nullSafe(scan.getTlsIssuer()));
            row(tls, "Valid from", format(scan.getTlsValidFrom()));
            row(tls, "Valid until", format(scan.getTlsValidTo()));
            row(tls, "Days remaining", scan.getTlsDaysRemaining() == null ? "-" : String.valueOf(scan.getTlsDaysRemaining()));
            row(tls, "Protocol / cipher", nullSafe(scan.getTlsProtocol()) + " / " + nullSafe(scan.getTlsCipherSuite()));
            if (scan.getTlsError() != null) {
                row(tls, "Validation error", scan.getTlsError());
            }
            document.add(tls);

            // 9-10: headers and cookies
            section(document, "4. Security Header Assessment");
            document.add(checkTable(list, FindingCategory.SECURITY_HEADERS));
            section(document, "5. Cookie Security Assessment");
            document.add(new Paragraph("Only cookie names and security attributes are assessed; cookie values are never "
                    + "collected or stored.", SMALL));
            document.add(spacer());
            document.add(checkTable(list, FindingCategory.COOKIES));

            // 11: findings
            section(document, "6. Security Findings");
            List<Finding> failed = list.stream().filter(f -> !f.isPassed()).toList();
            if (failed.isEmpty()) {
                document.add(new Paragraph(completed ? "No security findings were identified." : "Not assessed.", BODY));
            }
            for (Finding f : failed) {
                PdfPTable box = new PdfPTable(1);
                box.setWidthPercentage(100);
                box.setSpacingAfter(6);
                PdfPCell head = new PdfPCell(new Phrase("[" + f.getSeverity() + "] " + f.getTitle()
                        + "  -  " + f.getCategory().getLabel(), HEADER_CELL));
                head.setBackgroundColor(severityColor(f.getSeverity()));
                head.setPadding(5);
                head.setBorderColor(BORDER);
                box.addCell(head);
                Paragraph body = new Paragraph();
                body.add(new Chunk(nullSafe(f.getDescription()) + "\n", BODY));
                body.add(new Chunk("Evidence: ", BODY_BOLD));
                body.add(new Chunk(nullSafe(f.getEvidence()) + "\n", BODY));
                body.add(new Chunk("Recommendation: ", BODY_BOLD));
                body.add(new Chunk(nullSafe(f.getRecommendation()), BODY));
                PdfPCell content = new PdfPCell(body);
                content.setPadding(6);
                content.setBorderColor(BORDER);
                box.addCell(content);
                document.add(box);
            }

            // 12: recommended improvements
            section(document, "7. Recommended Improvements");
            List<String> recommendations = failed.stream()
                    .filter(f -> f.getRecommendation() != null && f.getSeverity().getDeduction() > 0)
                    .map(f -> f.getSeverity() + ": " + f.getRecommendation()).distinct().toList();
            if (recommendations.isEmpty()) {
                document.add(new Paragraph("No configuration changes are required based on the passive checks.", BODY));
            }
            int n = 1;
            for (String r : recommendations) {
                document.add(new Paragraph(n++ + ". " + r, BODY));
            }

            // 13: summary
            section(document, "8. Final Assessment Summary");
            document.add(new Paragraph(summary(scan), BODY));
            document.add(spacer());
            document.add(new Paragraph("Disclaimer: " + RiskScoringService.DISCLAIMER, SMALL));
            document.close();
        } catch (DocumentException e) {
            throw new IllegalStateException("Failed to generate PDF report", e);
        }
        return out.toByteArray();
    }

    static String summary(ScanRecord scan) {
        if (scan.getStatus() != ScanStatus.COMPLETED) {
            return "The assessment of " + scan.getTarget().getName() + " could not be completed: "
                    + nullSafe(scan.getErrorMessage()) + " Verify that the website is reachable and scan again.";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("The passive security assessment of ").append(scan.getTarget().getName()).append(" (")
                .append(scan.getTarget().getUrl()).append(") achieved a configuration security score of ")
                .append(scan.getScore()).append("/100, classified as ").append(scan.getRiskLevel().getLabel()).append(". ");
        sb.append(Boolean.TRUE.equals(scan.getHttpsAvailable())
                ? "The site is available over HTTPS"
                : "The site is NOT available over a trusted HTTPS connection");
        if (scan.getTlsDaysRemaining() != null) {
            sb.append(" and its certificate is valid for ").append(scan.getTlsDaysRemaining()).append(" more day(s)");
        }
        sb.append(". ").append(scan.getTotalFindings()).append(" finding(s) were identified");
        if (scan.getCriticalCount() + scan.getHighCount() > 0) {
            sb.append(", including ").append(scan.getCriticalCount()).append(" critical and ")
                    .append(scan.getHighCount()).append(" high severity issue(s) that should be fixed first");
        }
        sb.append(". Applying the recommended improvements and re-scanning will raise the score. ");
        sb.append("Continuous monitoring is recommended to detect configuration changes and certificate expiry.");
        return sb.toString();
    }

    private PdfPTable checkTable(List<Finding> list, FindingCategory category) {
        PdfPTable t = table(new float[] {2.4f, 0.9f, 1.1f, 3f, 3f}, "Check", "Status", "Severity", "Detected value",
                "Recommendation");
        List<Finding> items = list.stream().filter(f -> f.getCategory() == category).toList();
        if (items.isEmpty()) {
            PdfPCell none = new PdfPCell(new Phrase("Not assessed (no HTTP response available).", BODY));
            none.setColspan(5);
            none.setPadding(5);
            none.setBorderColor(BORDER);
            t.addCell(none);
        }
        for (Finding f : items) {
            cell(t, f.getTitle());
            PdfPCell status = new PdfPCell(new Phrase(f.isPassed() ? "PASS" : "FAIL",
                    FontFactory.getFont(FontFactory.HELVETICA_BOLD, 8, f.isPassed() ? new Color(21, 128, 61) : new Color(185, 28, 28))));
            status.setPadding(4);
            status.setBorderColor(BORDER);
            t.addCell(status);
            cell(t, f.isPassed() ? "-" : f.getSeverity().name());
            cell(t, nullSafe(f.getEvidence()));
            cell(t, f.isPassed() ? "-" : nullSafe(f.getRecommendation()));
        }
        return t;
    }

    private static PdfPTable table(float[] widths, String... headers) {
        PdfPTable t = new PdfPTable(widths);
        t.setWidthPercentage(100);
        t.setHeaderRows(1);
        for (String h : headers) {
            PdfPCell c = new PdfPCell(new Phrase(h, HEADER_CELL));
            c.setBackgroundColor(NAVY);
            c.setPadding(5);
            c.setBorderColor(BORDER);
            t.addCell(c);
        }
        return t;
    }

    private static PdfPTable keyValueTable() {
        PdfPTable t = new PdfPTable(new float[] {1.3f, 3});
        t.setWidthPercentage(100);
        return t;
    }

    private static void row(PdfPTable t, String key, String value) {
        PdfPCell k = new PdfPCell(new Phrase(key, BODY_BOLD));
        k.setBackgroundColor(LIGHT);
        k.setPadding(5);
        k.setBorderColor(BORDER);
        t.addCell(k);
        cell(t, value);
    }

    private static void cell(PdfPTable t, String value) {
        PdfPCell c = new PdfPCell(new Phrase(nullSafe(value), SMALL));
        c.setPadding(4);
        c.setBorderColor(BORDER);
        t.addCell(c);
    }

    private static void section(Document document, String title) throws DocumentException {
        Paragraph p = new Paragraph(title, H2);
        p.setSpacingBefore(14);
        p.setSpacingAfter(6);
        document.add(p);
    }

    private static Paragraph spacer() {
        return new Paragraph(" ", SMALL);
    }

    private static String format(Instant instant) {
        return instant == null ? "-" : DATE.format(instant);
    }

    private static String yesNo(Boolean value) {
        return value == null ? "Not determined" : value ? "Yes" : "No";
    }

    private static String nullSafe(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }

    private static Color scoreColor(int score) {
        if (score >= 75) {
            return new Color(21, 128, 61);
        }
        if (score >= 50) {
            return new Color(180, 120, 0);
        }
        return new Color(185, 28, 28);
    }

    private static Color severityColor(Severity severity) {
        return switch (severity) {
            case CRITICAL -> new Color(127, 29, 29);
            case HIGH -> new Color(185, 28, 28);
            case MEDIUM -> new Color(180, 100, 0);
            case LOW -> new Color(30, 90, 160);
            case INFORMATIONAL -> new Color(90, 100, 115);
        };
    }

    /** Page footer with project name and page number. */
    private static final class Footer extends PdfPageEventHelper {
        @Override
        public void onEndPage(PdfWriter writer, Document document) {
            Rectangle page = document.getPageSize();
            ColumnText.showTextAligned(writer.getDirectContent(), Element.ALIGN_LEFT,
                    new Phrase("Zero Trust Security Assessment - Confidential", SMALL), 40, 25, 0);
            ColumnText.showTextAligned(writer.getDirectContent(), Element.ALIGN_RIGHT,
                    new Phrase("Page " + writer.getPageNumber(), SMALL), page.getWidth() - 40, 25, 0);
        }
    }
}
