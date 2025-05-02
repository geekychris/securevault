package com.example.securevault.model;

/**
 * Options for listing secrets.
 */
public class ListOptions {
    private boolean recursive;

    /**
     * Checks if secrets should be listed recursively.
     *
     * @return true if secrets should be listed recursively
     */
    public boolean isRecursive() {
        return recursive;
    }

    /**
     * Sets whether secrets should be listed recursively.
     *
     * @param recursive whether secrets should be listed recursively
     */
    public void setRecursive(boolean recursive) {
        this.recursive = recursive;
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
     * Builder for creating list options.
     */
    public static class Builder {
        private final ListOptions options = new ListOptions();

        /**
         * Sets whether secrets should be listed recursively.
         *
         * @param recursive whether secrets should be listed recursively
         * @return this builder
         */
        public Builder recursive(boolean recursive) {
            options.setRecursive(recursive);
            return this;
        }

        /**
         * Builds the options.
         *
         * @return the options
         */
        public ListOptions build() {
            return options;
        }
    }
}

