package org.example.redoor.scan;

public record DashboardResponse(
        long totalScans,
        long runningScans,
        long completedScans,
        long failedScans,
        long totalFindings,
        long highRiskFindings
) {
}
