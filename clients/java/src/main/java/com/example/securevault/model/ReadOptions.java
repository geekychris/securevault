package com.example.securevault.model;

/**
 * Options for reading a secret.
 */
public class ReadOptions {
    private int version;

    /**
     * Gets the version of the secret to read.
     *
     * @return the version
     */
    public int getVersion() {
        return version;
    }

    /**
     * Sets the version of the secret to read.
     *
     * @param version the version
     */
    public void setVersion(int version) {
        this.version = version;
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
     * Builder for creating read options.
     */
    public static class Builder {
        private final ReadOptions options = new ReadOptions();

        /**
         * Sets the version of the secret to read.
         *
         * @param version the version
         * @return this builder
         */
        public Builder version(int version) {
            options.setVersion(version);
            return this;
        }

        /**
         * Builds the options.
         *
         * @return the options
         */
        public ReadOptions build() {
            return options;
        }
    }
}

