package com.zerotrust.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import com.zerotrust.entity.MonitoringEvent;

public interface MonitoringEventRepository extends MongoRepository<MonitoringEvent, Long> {

    @Query(value = "{ 'config': ?0 }", sort = "{ 'checkedAt': -1 }")
    Page<MonitoringEvent> findByConfigIdOrderByCheckedAtDesc(Long configId, Pageable pageable);

    @Query(value = "{ 'config': ?0 }", delete = true)
    void deleteByConfigId(Long configId);
}
