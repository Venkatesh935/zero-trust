package com.zerotrust.repository;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.zerotrust.entity.AuditLog;

public interface AuditLogRepository extends MongoRepository<AuditLog, Long> {
}
