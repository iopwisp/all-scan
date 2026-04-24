package org.example.redoor.scan;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record ScanCreatedResponse(
        UUID id,
        String targetUrl,
        ScanType scanType,
        List<CheckType> checks,
        ScanStatus status,
        int progress,
        String stage,
        Instant createdAt
) {
}
