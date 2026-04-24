package org.example.redoor.scan;

public record ScanStatusResponse(
        int progress,
        String stage,
        ScanStatus status
) {
}
