package com.zerotrust.repository;

import java.time.Instant;

import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;

import com.zerotrust.entity.ScanRecord;
import com.zerotrust.entity.ScanStatus;

class ScanRecordRepositoryImpl implements ScanRecordRepositoryCustom {

    private final MongoOperations mongo;

    ScanRecordRepositoryImpl(MongoOperations mongo) {
        this.mongo = mongo;
    }

    @Override
    public int failInterruptedScans(ScanStatus running, ScanStatus failed, Instant now, String message) {
        Update update = new Update().set("status", failed).set("completedAt", now).set("errorMessage", message);
        return (int) mongo.updateMulti(Query.query(Criteria.where("status").is(running)), update, ScanRecord.class)
                .getModifiedCount();
    }
}
