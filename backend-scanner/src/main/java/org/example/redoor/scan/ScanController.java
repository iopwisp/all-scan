package org.example.redoor.scan;

import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ScanController {

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    @GetMapping("/dashboard")
    public DashboardResponse dashboard() {
        return scanService.getDashboard();
    }

    @GetMapping("/scans")
    public List<ScanSummaryResponse> history() {
        return scanService.getHistory();
    }

    @GetMapping("/reports")
    public List<ScanSummaryResponse> reports() {
        return scanService.getReports();
    }

    @PostMapping("/scans")
    public ResponseEntity<ScanCreatedResponse> createScan(@Valid @RequestBody CreateScanRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(scanService.createScan(request));
    }

    @GetMapping("/scans/{id}")
    public ScanSummaryResponse getScan(@PathVariable UUID id) {
        return scanService.getScanById(id);
    }

    @GetMapping("/scans/{id}/status")
    public ScanStatusResponse status(@PathVariable UUID id) {
        return scanService.getStatus(id);
    }

    @GetMapping("/scans/{id}/results")
    public ScanResultsResponse results(@PathVariable UUID id) {
        return scanService.getResults(id);
    }

    @GetMapping(value = "/scans/{id}/report", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> report(@PathVariable UUID id) {
        byte[] pdf = scanService.getReport(id);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename("scan-" + id + ".pdf").build().toString())
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdf);
    }
}
