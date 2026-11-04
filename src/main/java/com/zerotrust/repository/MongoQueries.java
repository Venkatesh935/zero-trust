package com.zerotrust.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.query.Query;

/** Helpers for filtered, paged queries built with {@link Query}. */
public final class MongoQueries {

    private MongoQueries() {
    }

    public static <T> Page<T> page(MongoOperations mongo, Query query, Pageable pageable, Class<T> type) {
        long total = mongo.count(query, type);
        List<T> content = mongo.find(Query.of(query).with(pageable), type);
        return new PageImpl<>(content, pageable, total);
    }
}
