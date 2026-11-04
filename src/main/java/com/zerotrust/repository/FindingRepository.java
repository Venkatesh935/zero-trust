package com.zerotrust.repository;

import java.util.List;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import com.zerotrust.entity.Finding;

public interface FindingRepository extends MongoRepository<Finding, Long>, FindingRepositoryCustom {

    @Query(value = "{ 'scan': ?0 }", sort = "{ '_id': 1 }")
    List<Finding> findByScanIdOrderByIdAsc(Long scanId);

    void deleteByTargetId(Long targetId);
}
