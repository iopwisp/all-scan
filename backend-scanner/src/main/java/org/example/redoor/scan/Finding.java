package org.example.redoor.scan;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.util.UUID;

@Entity
@Table(name = "findings")
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "scan_id", nullable = false)
    private ScanJob scanJob;

    @Column(nullable = false, length = 40)
    private String type;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Severity severity;

    @Column(nullable = false, length = 2048)
    private String url;

    @Column(length = 255)
    private String parameter;

    @Column(nullable = false, length = 2000)
    private String description;

    @Column(nullable = false, length = 2000)
    private String recommendation;

    @Column(name = "owasp_category", nullable = false, length = 255)
    private String owaspCategory;

    @Column(length = 1000)
    private String payload;

    @Column(name = "ai_remediation", length = 2000)
    private String aiRemediation;

    protected Finding() {
    }

    public UUID getId() {
        return id;
    }

    public ScanJob getScanJob() {
        return scanJob;
    }

    public void setScanJob(ScanJob scanJob) {
        this.scanJob = scanJob;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getParameter() {
        return parameter;
    }

    public void setParameter(String parameter) {
        this.parameter = parameter;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }

    public String getOwaspCategory() {
        return owaspCategory;
    }

    public void setOwaspCategory(String owaspCategory) {
        this.owaspCategory = owaspCategory;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getAiRemediation() {
        return aiRemediation;
    }

    public void setAiRemediation(String aiRemediation) {
        this.aiRemediation = aiRemediation;
    }
}
