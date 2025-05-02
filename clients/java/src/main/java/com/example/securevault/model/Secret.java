package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;
import java.util.Map;

/**
 * Represents a secret stored in SecureVault.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Secret {
    private Map<String, Object> data;
    private SecretMetadataInfo metadata;

    /**
     * Gets the secret data.
     *
     * @return the secret data
     */
    public Map<String, Object> getData() {
        return data;
    }

    /**
     * Sets the secret data.
     *
     * @param data the secret data
     */
    public void setData(Map<String, Object> data) {
        this.data = data;
    }

    /**
     * Gets the secret metadata.
     *
     * @return the secret metadata
     */
    public SecretMetadataInfo getMetadata() {
        return metadata;
    }

    /**
     * Sets the secret metadata.
     *
     * @param metadata the secret metadata
     */
    public void setMetadata(SecretMetadataInfo metadata) {
        this.metadata = metadata;
    }

    /**
     * Inner class for metadata included directly with a secret.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class SecretMetadataInfo {
        private Instant createdTime;
        private int version;
        private int currentVersion;

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
    }
}

package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;
import java.util.Map;

/**
 * Represents a secret stored in SecureVault.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Secret {
    private Map<String, Object> data;
    private SecretMetadataInfo metadata;

    /**
     * Gets the secret data.
     *
     * @return the secret data
     */
    public Map<String, Object> getData() {
        return data;
    }

    /**
     * Sets the secret data.
     *
     * @param data the secret data
     */
    public void setData(Map<String, Object> data) {
        this.data = data;
    }

    /**
     * Gets the secret metadata.
     *
     * @return the secret metadata
     */
    public SecretMetadataInfo getMetadata() {
        return metadata;
    }

    /**
     * Sets the secret metadata.
     *
     * @param metadata the secret metadata
     */
    public void setMetadata(SecretMetadataInfo metadata) {
        this.metadata = metadata;
    }

    /**
     * Inner class for metadata included directly with a secret.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class SecretMetadataInfo {
        private Instant createdTime;
        private int version;
        private int currentVersion;

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
    }
}

