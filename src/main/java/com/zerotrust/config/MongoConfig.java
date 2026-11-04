package com.zerotrust.config;

import static org.springframework.data.mongodb.core.query.Criteria.where;
import static org.springframework.data.mongodb.core.query.Query.query;

import java.time.Instant;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.event.BeforeConvertCallback;
import org.springframework.data.mongodb.core.query.Update;

import com.zerotrust.entity.LongIdEntity;
import com.zerotrust.entity.Timestamped;

/**
 * MongoDB persistence setup. Documents keep numeric IDs (so the REST API is
 * unchanged); each collection has its own atomic counter in {@code counters}.
 */
@Configuration
public class MongoConfig {

    @Bean
    BeforeConvertCallback<LongIdEntity> longIdAndTimestampCallback(ObjectProvider<MongoOperations> mongo) {
        return new LongIdAndTimestampCallback(mongo);
    }

    static final class LongIdAndTimestampCallback implements BeforeConvertCallback<LongIdEntity> {

        // resolved lazily: the template itself depends on the converter that holds this callback
        private final ObjectProvider<MongoOperations> mongo;

        LongIdAndTimestampCallback(ObjectProvider<MongoOperations> mongo) {
            this.mongo = mongo;
        }

        @Override
        public LongIdEntity onBeforeConvert(LongIdEntity entity, String collection) {
            if (entity.getId() == null) {
                entity.assignId(nextId(collection));
            }
            if (entity instanceof Timestamped timestamped) {
                timestamped.markSaved(Instant.now());
            }
            return entity;
        }

        private long nextId(String collection) {
            Counter counter = mongo.getObject().findAndModify(query(where("_id").is(collection)), new Update().inc("seq", 1),
                    FindAndModifyOptions.options().upsert(true).returnNew(true), Counter.class);
            return counter.seq;
        }
    }

    @Document("counters")
    static class Counter {

        @Id
        String id;

        long seq;
    }
}
