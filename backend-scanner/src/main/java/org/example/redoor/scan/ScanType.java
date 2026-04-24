package org.example.redoor.scan;

import com.fasterxml.jackson.annotation.JsonAlias;

public enum ScanType {
    @JsonAlias({"fast", "FAST", "quick"})
    QUICK,

    @JsonAlias({"deep", "DEEP", "full", "owasp-full", "OWASP_FULL", "owasp_full"})
    FULL
}
