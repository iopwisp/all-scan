package org.example.redoor.scan;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.example.redoor.common.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
public class ScanService {

    private final ScanJobRepository scanJobRepository;
    private final FindingRepository findingRepository;
    private final ScannerEngineService scannerEngineService;
    private final PdfReportService pdfReportService;

    public ScanService(
            ScanJobRepository scanJobRepository,
            FindingRepository findingRepository,
            ScannerEngineService scannerEngineService,
            PdfReportService pdfReportService
    ) {
        this.scanJobRepository = scanJobRepository;
        this.findingRepository = findingRepository;
        this.scannerEngineService = scannerEngineService;
        this.pdfReportService = pdfReportService;
    }

    @Transactional
    public ScanCreatedResponse createScan(CreateScanRequest request) {
        String normalizedTargetUrl = normalizeTargetUrl(request.targetUrl());

        ScanJob scanJob = new ScanJob();
        scanJob.setTargetUrl(normalizedTargetUrl);
        scanJob.setScanType(request.scanType());
        scanJob.setRequestedChecks(request.resolvedChecks());
        scanJob.setStatus(ScanStatus.QUEUED);
        scanJob.setProgress(0);
        scanJob.setRiskScore(0);
        scanJob.setStage("Queued");
        scanJob.setCreatedAt(Instant.now());

        ScanJob savedScanJob = scanJobRepository.saveAndFlush(scanJob);
        UUID scanId = savedScanJob.getId();

        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    scannerEngineService.executeScan(scanId);
                }
            });
        } else {
            scannerEngineService.executeScan(scanId);
        }

        return ScanResponseMapper.toCreatedResponse(savedScanJob);
    }

    @Transactional(readOnly = true)
    public List<ScanSummaryResponse> getHistory() {
        return ScanResponseMapper.toSummaryResponses(scanJobRepository.findAllByOrderByCreatedAtDesc());
    }

    @Transactional(readOnly = true)
    public List<ScanSummaryResponse> getReports() {
        return ScanResponseMapper.toSummaryResponses(
                scanJobRepository.findAllByStatusOrderByCreatedAtDesc(ScanStatus.COMPLETED)
        );
    }

    @Transactional(readOnly = true)
    public DashboardResponse getDashboard() {
        return new DashboardResponse(
                scanJobRepository.count(),
                scanJobRepository.countByStatus(ScanStatus.RUNNING) + scanJobRepository.countByStatus(ScanStatus.QUEUED),
                scanJobRepository.countByStatus(ScanStatus.COMPLETED),
                scanJobRepository.countByStatus(ScanStatus.FAILED),
                findingRepository.count(),
                findingRepository.countBySeverityIn(List.of(Severity.HIGH, Severity.CRITICAL))
        );
    }

    @Transactional(readOnly = true)
    public ScanSummaryResponse getScanById(UUID id) {
        return ScanResponseMapper.toSummaryResponse(findScanOrThrow(id));
    }

    @Transactional(readOnly = true)
    public ScanStatusResponse getStatus(UUID id) {
        return ScanResponseMapper.toStatusResponse(findScanOrThrow(id));
    }

    @Transactional(readOnly = true)
    public ScanResultsResponse getResults(UUID id) {
        return ScanResponseMapper.toResultsResponse(findScanOrThrow(id));
    }

    @Transactional(readOnly = true)
    public byte[] getReport(UUID id) {
        return pdfReportService.generate(findScanOrThrow(id));
    }

    private ScanJob findScanOrThrow(UUID id) {
        return scanJobRepository.findById(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Scan not found: " + id));
    }

    private String normalizeTargetUrl(String rawTargetUrl) {
        URI targetUri;
        try {
            targetUri = URI.create(rawTargetUrl.trim());
        } catch (IllegalArgumentException exception) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Target URL must be a valid absolute HTTP URL.");
        }

        String scheme = targetUri.getScheme();
        if (scheme == null || targetUri.getHost() == null
                || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Target URL must be a valid absolute HTTP URL.");
        }

        return targetUri.toString();
    }
}
