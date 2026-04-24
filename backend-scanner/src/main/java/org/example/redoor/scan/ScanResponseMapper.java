package org.example.redoor.scan;

import java.util.List;

public final class ScanResponseMapper {

    private ScanResponseMapper() {
    }

    public static ScanCreatedResponse toCreatedResponse(ScanJob scanJob) {
        return new ScanCreatedResponse(
                scanJob.getId(),
                scanJob.getTargetUrl(),
                scanJob.getScanType(),
                scanJob.requestedChecksAsList(),
                scanJob.getStatus(),
                scanJob.getProgress(),
                scanJob.getStage(),
                scanJob.getCreatedAt()
        );
    }

    public static ScanStatusResponse toStatusResponse(ScanJob scanJob) {
        return new ScanStatusResponse(scanJob.getProgress(), scanJob.getStage(), scanJob.getStatus());
    }

    public static ScanResultsResponse toResultsResponse(ScanJob scanJob) {
        return new ScanResultsResponse(
                scanJob.getId(),
                scanJob.getTargetUrl(),
                scanJob.getScanType(),
                scanJob.requestedChecksAsList(),
                scanJob.getStatus(),
                scanJob.getProgress(),
                scanJob.getStage(),
                scanJob.getRiskScore(),
                scanJob.getCreatedAt(),
                scanJob.getFindings().stream().map(ScanResponseMapper::toFindingResponse).toList()
        );
    }

    public static ScanSummaryResponse toSummaryResponse(ScanJob scanJob) {
        return new ScanSummaryResponse(
                scanJob.getId(),
                scanJob.getTargetUrl(),
                scanJob.getScanType(),
                scanJob.requestedChecksAsList(),
                scanJob.getStatus(),
                scanJob.getProgress(),
                scanJob.getStage(),
                scanJob.getRiskScore(),
                scanJob.getCreatedAt(),
                scanJob.getFindings().size()
        );
    }

    public static List<ScanSummaryResponse> toSummaryResponses(List<ScanJob> scanJobs) {
        return scanJobs.stream().map(ScanResponseMapper::toSummaryResponse).toList();
    }

    private static FindingResponse toFindingResponse(Finding finding) {
        return new FindingResponse(
                finding.getId(),
                finding.getType(),
                finding.getSeverity(),
                finding.getUrl(),
                finding.getParameter(),
                finding.getDescription(),
                finding.getRecommendation(),
                finding.getOwaspCategory(),
                finding.getPayload(),
                finding.getAiRemediation()
        );
    }
}
