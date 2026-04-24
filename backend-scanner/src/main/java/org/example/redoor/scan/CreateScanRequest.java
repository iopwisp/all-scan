package org.example.redoor.scan;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Arrays;
import java.util.List;

public record CreateScanRequest(
        @NotBlank(message = "Target URL is required.") String targetUrl,
        @NotNull(message = "Scan type is required.") ScanType scanType,
        List<CheckType> checks
) {

    public List<CheckType> resolvedChecks() {
        if (checks == null || checks.isEmpty()) {
            return Arrays.stream(CheckType.values()).toList();
        }
        return checks.stream().distinct().toList();
    }
}
