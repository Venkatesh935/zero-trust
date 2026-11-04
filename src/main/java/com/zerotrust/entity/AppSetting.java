package com.zerotrust.entity;

import java.time.Instant;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * Key/value application setting that administrators can change at runtime,
 * for example whether self-registration is enabled.
 */
@Document("app_settings")
public class AppSetting {

    @Id
    private String key;

    private String value;

    private Instant updatedAt = Instant.now();

    protected AppSetting() {
    }

    public AppSetting(String key, String value) {
        this.key = key;
        this.value = value;
    }

    public String getKey() {
        return key;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
        this.updatedAt = Instant.now();
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
