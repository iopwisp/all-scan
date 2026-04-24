package org.example.redoor.scan;

import java.util.UUID;

public record FindingResponse(
        UUID id,
        String type,
        Severity severity,
        String url,
        String parameter,
        String description,
        String recommendation,
        String owaspCategory,
        String payload,
        String aiRemediation
) {
}
