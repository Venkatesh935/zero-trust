package com.zerotrust.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.zerotrust.entity.AppUser;
import com.zerotrust.entity.Role;

public interface AppUserRepository extends MongoRepository<AppUser, Long> {

    Optional<AppUser> findByUsernameIgnoreCase(String username);

    boolean existsByUsernameIgnoreCase(String username);

    long countByRoleAndEnabledTrue(Role role);

    List<AppUser> findAllByOrderByUsernameAsc();

    List<AppUser> findByIdIn(List<Long> ids);
}
