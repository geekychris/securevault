package com.example.securevault.model;

import java.util.Map;

/**
 * Options for writing a secret.
 */
public class WriteOptions {
    private Map<String, Object> metadata;

    /**
     * Gets the metadata to associate with the secret.
     *
     * @return the metadata
     */
    public Map<String, Object> getMetadata() {
        return metadata;
    }

    /**
     * Sets the metadata to associate with the secret.
     *
     * @param metadata the metadata
     */
    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }

    /**
     * Creates a new options builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for creating write options.
     */
    public static class Builder {
        private final WriteOptions options = new WriteOptions();

        /**
         * Sets the metadata to associate with the secret.
         *
         * @param metadata the metadata
         * @return this builder
         */
        public Builder metadata(Map<String, Object> metadata) {
            options.setMetadata(metadata);
            return this;
        }

        /**
         * Builds the options.
         *
         * @return the options
         */
        public WriteOptions build() {
            return options;
        }
    }
}

