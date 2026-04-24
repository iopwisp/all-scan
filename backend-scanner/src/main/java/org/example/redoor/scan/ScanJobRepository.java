package org.example.redoor.scan;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ScanJobRepository extends JpaRepository<ScanJob, UUID> {

    List<ScanJob> findAllByOrderByCreatedAtDesc();

    List<ScanJob> findAllByStatusOrderByCreatedAtDesc(ScanStatus status);

    long countByStatus(ScanStatus status);
}
