package com.zerotrust.entity;

import org.springframework.data.annotation.Id;

/**
 * Base class for documents that use a numeric ID. The ID is assigned from a
 * collection-specific sequence on first save (see {@code MongoConfig}), which
 * keeps the public API identifiers the same short numbers as before.
 */
public abstract class LongIdEntity {

    @Id
    private Long id;

    public Long getId() {
        return id;
    }

    /** Called once by the persistence layer before the first save. */
    public void assignId(Long id) {
        this.id = id;
    }
}
