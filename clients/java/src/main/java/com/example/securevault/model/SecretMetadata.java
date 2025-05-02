package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;
import java.util.Map;

/**
 * Metadata about a secret.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecretMetadata {
    private Map<String, VersionMetadata> versions;
    private int currentVersion;
    private Instant createdTime;
    private Instant lastModified;

    /**
     * Gets version metadata for all versions of the secret.
     *
     * @return the version metadata map
     */
    public Map<String, VersionMetadata> getVersions() {
        return versions;
    }

    /**
     * Sets version metadata for all versions of the secret.
     *
     * @param versions the version metadata map
     */
    public void setVersions(Map<String, VersionMetadata> versions) {
        this.versions = versions;
    }

    /**
     * Gets the current version number.
     *
     * @return the current version
     */
    public int getCurrentVersion() {
        return currentVersion;
    }

    /**
     * Sets the current version number.
     *
     * @param currentVersion the current version
     */
    public void setCurrentVersion(int currentVersion) {
        this.currentVersion = currentVersion;
    }

    /**
     * Gets the time the secret was created.
     *
     * @return the created time
     */
    public Instant getCreatedTime() {
        return createdTime;
    }

    /**
     * Sets the time the secret was created.
     *
     * @param createdTime the created time
     */
    public void setCreatedTime(Instant createdTime) {
        this.createdTime = createdTime;
    }

    /**
     * Gets the time the secret was last modified.
     *
     * @return the last modified time
     */
    public Instant getLastModified() {
        return lastModified;
    }

    /**
     * Sets the time the secret was last modified.
     *
     * @param lastModified the last modified time
     */
    public void setLastModified(Instant lastModified) {
        this.lastModified = lastModified;
    }
}

package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;
import java.util.Map;

/**
 * Metadata about a secret.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecretMetadata {
    private Map<String, VersionMetadata> versions;
    private int currentVersion;
    private Instant createdTime;
    private Instant lastModified;

    /**
     * Gets version metadata for all versions of the secret.
     *
     * @return the version metadata map
     */
    public Map<String, VersionMetadata> getVersions() {
        return versions;
    }

    /**
     * Sets version metadata for all versions of the secret.
     *
     * @param versions the version metadata map
     */
    public void setVersions(Map<String, VersionMetadata> versions) {
        this.versions = versions;
    }

    /**
     * Gets the current version number.
     *
     * @return the current version
     */
    public int getCurrentVersion() {
        return currentVersion;
    }

    /**
     * Sets the current version number.
     *
     * @param currentVersion the current version
     */
    public void setCurrentVersion(int currentVersion) {
        this.currentVersion = currentVersion;
    }

    /**
     * Gets the time the secret was created.
     *
     * @return the created time
     */
    public Instant getCreatedTime() {
        return createdTime;
    }

    /**
     * Sets the time the secret was created.
     *
     * @param createdTime the created time
     */
    public void setCreatedTime(Instant createdTime) {
        this.createdTime = createdTime;
    }

    /**
     * Gets the time the secret was last modified.
     *
     * @return the last modified time
     */
    public Instant getLastModified() {
        return lastModified;
    }

    /**
     * Sets the time the secret was last modified.
     *
     * @param lastModified the last modified time
     */
    public void setLastModified(Instant lastModified) {
        this.lastModified = lastModified;
    }
}

