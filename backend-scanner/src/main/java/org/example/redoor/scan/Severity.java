package org.example.redoor.scan;

public enum Severity {
    LOW(5),
    MEDIUM(10),
    HIGH(20),
    CRITICAL(30);

    private final int scoreWeight;

    Severity(int scoreWeight) {
        this.scoreWeight = scoreWeight;
    }

    public int getScoreWeight() {
        return scoreWeight;
    }
}
