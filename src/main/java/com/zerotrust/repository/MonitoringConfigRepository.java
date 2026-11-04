package com.zerotrust.repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import com.zerotrust.entity.MonitoringConfig;

public interface MonitoringConfigRepository extends MongoRepository<MonitoringConfig, Long> {

    List<MonitoringConfig> findAllByOrderByIdAsc();

    @Query(value = "{ 'target': { $in: ?0 } }", sort = "{ '_id': 1 }")
    List<MonitoringConfig> findByTargetIdInOrderByIdAsc(Collection<Long> targetIds);

    @Query("{ 'target': ?0 }")
    Optional<MonitoringConfig> findByTargetId(Long targetId);

    @Query(value = "{ 'target': ?0 }", exists = true)
    boolean existsByTargetId(Long targetId);

    long countByEnabledTrue();

    @Query(value = "{ 'enabled': true, 'target': { $in: ?0 } }", count = true)
    long countByEnabledTrueAndTargetIdIn(Collection<Long> targetIds);

    List<MonitoringConfig> findByEnabledTrueAndNextRunAtLessThanEqualOrderByNextRunAtAsc(Instant now, Pageable pageable);
}
