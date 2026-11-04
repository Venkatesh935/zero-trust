package com.zerotrust.repository;

import java.util.List;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import com.zerotrust.entity.WebsiteTarget;

public interface WebsiteTargetRepository extends MongoRepository<WebsiteTarget, Long> {

    boolean existsByUrlIgnoreCase(String url);

    boolean existsByUrlIgnoreCaseAndIdNot(String url, Long id);

    List<WebsiteTarget> findAllByOrderByNameAsc();

    @Query(value = "{ 'assignedAnalysts': ?0 }", sort = "{ 'name': 1 }")
    List<WebsiteTarget> findAssignedTo(Long userId);

    /** Only the ID is loaded; used for access checks. */
    @Query(value = "{ 'assignedAnalysts': ?0 }", fields = "{ '_id': 1 }")
    List<WebsiteTarget> findAssignedIdsOnly(Long userId);

    default List<Long> findIdsAssignedTo(Long userId) {
        return findAssignedIdsOnly(userId).stream().map(WebsiteTarget::getId).toList();
    }

    @Query(value = "{ '_id': ?0, 'assignedAnalysts': ?1 }", exists = true)
    boolean isAssigned(Long targetId, Long userId);
}
