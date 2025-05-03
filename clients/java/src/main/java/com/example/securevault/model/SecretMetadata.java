package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Map;

/**
 * Metadata for a secret.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecretMetadata {
    @JsonProperty("created_time")
    private Instant createdTime;
    
    @JsonProperty("updated_time")
    private Instant updatedTime;
    
    @JsonProperty("version")
    private int version;
    
    @JsonProperty("current_version")
    private int currentVersion;
    
    @JsonProperty("versions")
    private Map<String, VersionMetadata> versions;
    
    @JsonProperty("metadata")
    private Map<String, String> metadata;

    /**
     * Gets the time when the secret was created.
     *
     * @return the created time
     */
    public Instant getCreatedTime() {
        return createdTime;
    }

    /**
     * Sets the time when the secret was created.
     *
     * @param createdTime the created time
     */
    public void setCreatedTime(Instant createdTime) {
        this.createdTime = createdTime;
    }

    /**
     * Gets the time when the secret was last updated.
     *
     * @return the updated time
     */
    public Instant getUpdatedTime() {
        return updatedTime;
    }

    /**
     * Sets the time when the secret was last updated.
     *
     * @param updatedTime the updated time
     */
    public void setUpdatedTime(Instant updatedTime) {
        this.updatedTime = updatedTime;
    }

    /**
     * Gets the version of the secret.
     *
     * @return the version
     */
    public int getVersion() {
        return version;
    }

    /**
     * Sets the version of the secret.
     *
     * @param version the version
     */
    public void setVersion(int version) {
        this.version = version;
    }

    /**
     * Gets the current version of the secret.
     *
     * @return the current version
     */
    public int getCurrentVersion() {
        return currentVersion;
    }

    /**
     * Sets the current version of the secret.
     *
     * @param currentVersion the current version
     */
    public void setCurrentVersion(int currentVersion) {
        this.currentVersion = currentVersion;
    }

    /**
     * Gets metadata for all versions of the secret.
     *
     * @return the versions metadata
     */
    public Map<String, VersionMetadata> getVersions() {
        return versions;
    }

    /**
     * Sets metadata for all versions of the secret.
     *
     * @param versions the versions metadata
     */
    public void setVersions(Map<String, VersionMetadata> versions) {
        this.versions = versions;
    }

    /**
     * Gets custom metadata for the secret.
     *
     * @return the metadata
     */
    public Map<String, String> getMetadata() {
        return metadata;
    }

    /**
     * Sets custom metadata for the secret.
     *
     * @param metadata the metadata
     */
    public void setMetadata(Map<String, String> metadata) {
        this.metadata = metadata;
    }
}
