package org.example.redoor.scan;

import java.util.Collection;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FindingRepository extends JpaRepository<Finding, UUID> {

    long countBySeverityIn(Collection<Severity> severities);
}
