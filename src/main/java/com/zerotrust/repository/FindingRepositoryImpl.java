package com.zerotrust.repository;

import java.util.Collection;
import java.util.List;

import org.bson.Document;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.aggregation.Aggregation;
import org.springframework.data.mongodb.core.query.Criteria;

import com.zerotrust.entity.Finding;
import com.zerotrust.entity.Severity;

class FindingRepositoryImpl implements FindingRepositoryCustom {

    private final MongoOperations mongo;

    FindingRepositoryImpl(MongoOperations mongo) {
        this.mongo = mongo;
    }

    @Override
    public List<Object[]> countFailedBySeverity(Collection<Long> scanIds) {
        Aggregation aggregation = Aggregation.newAggregation(
                Aggregation.match(Criteria.where("scan").in(scanIds).and("passed").is(false)),
                Aggregation.group("severity").count().as("total"));
        return mongo.aggregate(aggregation, Finding.class, Document.class).getMappedResults().stream()
                .map(row -> new Object[] { Severity.valueOf(row.getString("_id")),
                        ((Number) row.get("total")).longValue() })
                .toList();
    }
}
