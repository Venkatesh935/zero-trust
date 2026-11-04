package com.zerotrust.entity;

import java.time.Instant;

/**
 * Base class that maintains created/updated timestamps for documents. The
 * persistence layer calls {@link #markSaved} before every save.
 */
public abstract class Timestamped extends LongIdEntity {

    private Instant createdAt;

    private Instant updatedAt;

    public void markSaved(Instant now) {
        if (createdAt == null) {
            createdAt = now;
        }
        updatedAt = now;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
