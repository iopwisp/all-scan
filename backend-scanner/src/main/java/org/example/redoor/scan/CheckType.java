package org.example.redoor.scan;

import com.fasterxml.jackson.annotation.JsonAlias;

public enum CheckType {
    @JsonAlias({"xss"})
    XSS,

    @JsonAlias({"sqli"})
    SQLI,

    @JsonAlias({"csrf"})
    CSRF,

    @JsonAlias({"directoryScan", "directory_scan", "open_directories"})
    OPEN_DIRECTORIES,

    @JsonAlias({"configLeak", "config_leak", "leakage"})
    LEAKAGE
}
