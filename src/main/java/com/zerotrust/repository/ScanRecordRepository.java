package com.zerotrust.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import com.zerotrust.entity.ScanRecord;

public interface ScanRecordRepository extends MongoRepository<ScanRecord, Long>, ScanRecordRepositoryCustom {

    @Query(value = "{ 'target': ?0, '_id': { $lt: ?1 } }", sort = "{ '_id': -1 }")
    List<ScanRecord> findEarlierScans(Long targetId, Long id, Pageable pageable);

    /** The scan of the same target that ran immediately before the given scan. */
    default Optional<ScanRecord> findFirstByTargetIdAndIdLessThanOrderByIdDesc(Long targetId, Long id) {
        return findEarlierScans(targetId, id, PageRequest.of(0, 1)).stream().findFirst();
    }

    @Query(value = "{ 'target': { $in: ?0 } }", count = true)
    long countByTargetIdIn(List<Long> targetIds);

    @Query(value = "{ 'target': ?0 }", delete = true)
    void deleteByTargetId(Long targetId);
}
