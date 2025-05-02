package com.example.securevault.model;

import java.util.List;

/**
 * Options for deleting a secret.
 */
public class DeleteOptions {
    private List<Integer> versions;
    private boolean destroy;

    /**
     * Gets the versions to delete.
     *
     * @return the versions
     */
    public List<Integer> getVersions() {
        return versions;
    }

    /**
     * Sets the versions to delete.
     *
     * @param versions the versions
     */
    public void setVersions(List<Integer> versions) {
        this.versions = versions;
    }

    /**
     * Checks if the secret should be permanently destroyed.
     *
     * @return true if the secret should be permanently destroyed
     */
    public boolean isDestroy() {
        return destroy;
    }

    /**
     * Sets whether the secret should be permanently destroyed.
     *
     * @param destroy whether the secret should be permanently destroyed
     */
    public void setDestroy(boolean destroy) {
        this.destroy = destroy;
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
     * Builder for creating delete options.
     */
    public static class Builder {
        private final DeleteOptions options = new DeleteOptions();

        /**
         * Sets the versions to delete.
         *
         * @param versions the versions
         * @return this builder
         */
        public Builder versions(List<Integer> versions) {
            options.setVersions(versions);
            return this;
        }

        /**
         * Sets whether the secret should be permanently destroyed.
         *
         * @param destroy whether the secret should be permanently destroyed
         * @return this builder
         */
        public Builder destroy(boolean destroy) {
            options.setDestroy(destroy);
            return this;
        }

        /**
         * Builds the options.
         *
         * @return the options
         */
        public DeleteOptions build() {
            return options;
        }
    }
}

