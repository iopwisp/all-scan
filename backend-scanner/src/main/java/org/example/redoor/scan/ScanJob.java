package org.example.redoor.scan;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OrderBy;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Entity
@Table(name = "scan_jobs")
public class ScanJob {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "target_url", nullable = false, length = 2048)
    private String targetUrl;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private ScanStatus status;

    @Column(nullable = false)
    private int progress;

    @Column(nullable = false)
    private int riskScore;

    @Column(nullable = false, length = 255)
    private String stage;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "scan_type", nullable = false, length = 20)
    private ScanType scanType;

    @Column(name = "requested_checks", nullable = false, length = 255)
    private String requestedChecks;

    @OneToMany(mappedBy = "scanJob", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderBy("severity DESC, type ASC")
    private List<Finding> findings = new ArrayList<>();

    protected ScanJob() {
    }

    public UUID getId() {
        return id;
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public ScanStatus getStatus() {
        return status;
    }

    public void setStatus(ScanStatus status) {
        this.status = status;
    }

    public int getProgress() {
        return progress;
    }

    public void setProgress(int progress) {
        this.progress = progress;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }

    public String getStage() {
        return stage;
    }

    public void setStage(String stage) {
        this.stage = stage;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public ScanType getScanType() {
        return scanType;
    }

    public void setScanType(ScanType scanType) {
        this.scanType = scanType;
    }

    public String getRequestedChecks() {
        return requestedChecks;
    }

    public void setRequestedChecks(Collection<CheckType> checks) {
        this.requestedChecks = checks.stream()
                .map(Enum::name)
                .distinct()
                .sorted()
                .collect(Collectors.joining(","));
    }

    public List<CheckType> requestedChecksAsList() {
        if (requestedChecks == null || requestedChecks.isBlank()) {
            return List.of();
        }
        return Arrays.stream(requestedChecks.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .map(CheckType::valueOf)
                .toList();
    }

    public List<Finding> getFindings() {
        return findings;
    }

    public void addFinding(Finding finding) {
        findings.add(finding);
        finding.setScanJob(this);
    }
}
