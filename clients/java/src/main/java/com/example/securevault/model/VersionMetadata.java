package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;
import java.util.Map;

/**
 * Metadata about a specific version of a secret.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class VersionMetadata {
    private Instant createdTime;
    private String createdBy;
    private Instant deletedTime;
    private String deletedBy;
    private boolean isDestroyed;
    private Map<String, Object> customMetadata;

    /**
     * Gets the time this version was created.
     *
     * @return the created time
     */
    public Instant getCreatedTime() {
        return createdTime;
    }

    /**
     * Sets the time this version was created.
     *
     * @param createdTime the created time
     */
    public void setCreatedTime(Instant createdTime) {
        this.createdTime = createdTime;
    }

    /**
     * Gets the ID of who created this version.
     *
     * @return the creator ID
     */
    public String getCreatedBy() {
        return createdBy;
    }

    /**
     * Sets the ID of who created this version.
     *
     * @param createdBy the creator ID
     */
    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    /**
     * Gets the time this version was deleted.
     *
     * @return the deleted time
     */
    public Instant getDeletedTime() {
        return deletedTime;
    }

    /**
     * Sets the time this version was deleted.
     *
     * @param deletedTime the deleted time
     */
    public void setDeletedTime(Instant deletedTime) {
        this.deletedTime = deletedTime;
    }

    /**
     * Gets the ID of who deleted this version.
     *
     * @return the deleter ID
     */
    public String getDeletedBy() {
        return deletedBy;
    }

    /**
     * Sets the ID of who deleted this version.
     *
     * @param deletedBy the deleter ID
     */
    public void setDeletedBy(String deletedBy) {
        this.deletedBy = deletedBy;
    }

    /**
     * Checks if this version has been destroyed.
     *
     * @return true if this version has been destroyed
     */
    public boolean isDestroyed() {
        return isDestroyed;
    }

    /**
     * Sets whether this version has been destroyed.
     *
     * @param destroyed whether this version has been destroyed
     */
    public void setDestroyed(boolean destroyed) {
        isDestroyed = destroyed;
    }

    /**
     * Gets custom metadata for this version.
     *
     * @return the custom metadata
     */
    public Map<String, Object> getCustomMetadata() {
        return customMetadata;
    }

    /**
     * Sets custom metadata for this version.
     *
     * @param customMetadata the custom metadata
     */
    public void setCustomMetadata(Map<String, Object> customMetadata) {
        this.customMetadata = customMetadata;
    }
}

