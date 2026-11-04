package com.zerotrust.repository;

import java.util.Collection;
import java.util.List;

public interface FindingRepositoryCustom {

    /** Rows of [severity, count] for failed checks in the given scans. */
    List<Object[]> countFailedBySeverity(Collection<Long> scanIds);
}
