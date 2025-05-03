package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Options for listing secrets in the vault.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ListOptions {
    /**
     * Whether to list secrets recursively.
     * If true, all secrets under the path and its subdirectories will be listed.
     * If false, only secrets directly under the path will be listed.
     */
    @JsonProperty("recursive")
    private boolean recursive;
    
    /**
     * The prefix to filter secrets by.
     * If specified, only secrets with names starting with this prefix will be listed.
     */
    @JsonProperty("prefix")
    private String prefix;
    
    /**
     * Default constructor.
     */
    public ListOptions() {
    }
    
    /**
     * Gets whether to list secrets recursively.
     *
     * @return true if listing should be recursive, false otherwise
     */
    public boolean isRecursive() {
        return recursive;
    }
    
    /**
     * Sets whether to list secrets recursively.
     *
     * @param recursive true if listing should be recursive, false otherwise
     */
    public void setRecursive(boolean recursive) {
        this.recursive = recursive;
    }
    
    /**
     * Gets the prefix to filter secrets by.
     *
     * @return the prefix
     */
    public String getPrefix() {
        return prefix;
    }
    
    /**
     * Sets the prefix to filter secrets by.
     *
     * @param prefix the prefix
     */
    public void setPrefix(String prefix) {
        this.prefix = prefix;
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
         * Sets whether to list secrets recursively.
         *
         * @param recursive true if listing should be recursive, false otherwise
         * @return this builder
         */
        public Builder recursive(boolean recursive) {
            options.setRecursive(recursive);
            return this;
        }
        
        /**
         * Sets the prefix to filter secrets by.
         *
         * @param prefix the prefix
         * @return this builder
         */
        public Builder prefix(String prefix) {
            options.setPrefix(prefix);
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
