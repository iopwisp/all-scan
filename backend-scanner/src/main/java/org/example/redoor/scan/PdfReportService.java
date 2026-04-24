package org.example.redoor.scan;

import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import java.io.ByteArrayOutputStream;
import org.springframework.stereotype.Service;

@Service
public class PdfReportService {

    public byte[] generate(ScanJob scanJob) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            Document document = new Document(PageSize.A4, 36, 36, 36, 36);
            PdfWriter.getInstance(document, outputStream);
            document.open();

            Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18);
            Font sectionFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12);

            document.add(new Paragraph("Redoor Security Scan Report", titleFont));
            document.add(new Paragraph(" "));
            document.add(new Paragraph("Scan ID: " + scanJob.getId(), sectionFont));
            document.add(new Paragraph("Target URL: " + scanJob.getTargetUrl()));
            document.add(new Paragraph("Scan Type: " + scanJob.getScanType()));
            document.add(new Paragraph("Checks: " + scanJob.getRequestedChecks().replace(",", ", ")));
            document.add(new Paragraph("Status: " + scanJob.getStatus()));
            document.add(new Paragraph("Risk Score: " + scanJob.getRiskScore()));
            document.add(new Paragraph("Created At: " + scanJob.getCreatedAt()));
            document.add(new Paragraph(" "));

            PdfPTable table = new PdfPTable(new float[]{2.3f, 1.4f, 3.2f, 2.1f});
            table.setWidthPercentage(100);
            addHeaderCell(table, "Type");
            addHeaderCell(table, "Severity");
            addHeaderCell(table, "URL / Parameter");
            addHeaderCell(table, "OWASP");

            if (scanJob.getFindings().isEmpty()) {
                PdfPCell emptyCell = new PdfPCell(new Phrase("No findings detected."));
                emptyCell.setColspan(4);
                table.addCell(emptyCell);
            } else {
                for (Finding finding : scanJob.getFindings()) {
                    table.addCell(finding.getType());
                    table.addCell(finding.getSeverity().name());
                    table.addCell(finding.getUrl() + (finding.getParameter() == null ? "" : " [" + finding.getParameter() + "]"));
                    table.addCell(finding.getOwaspCategory());
                }
            }

            document.add(table);
            document.close();
            return outputStream.toByteArray();
        } catch (DocumentException exception) {
            throw new IllegalStateException("Failed to generate PDF report.", exception);
        }
    }

    private void addHeaderCell(PdfPTable table, String value) {
        PdfPCell cell = new PdfPCell(new Phrase(value));
        cell.setBackgroundColor(new java.awt.Color(230, 230, 230));
        table.addCell(cell);
    }
}
