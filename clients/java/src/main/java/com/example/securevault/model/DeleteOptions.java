package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Options for deleting secrets from the vault.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class DeleteOptions {
    /**
     * The list of versions to delete.
     * If not specified, the latest version is deleted.
     */
    @JsonProperty("versions")
    private List<Long> versions;
    
    /**
     * Whether to destroy the secret permanently.
     * If true, the secret data will be completely removed and cannot be recovered.
     * If false, the secret is only marked as deleted and can be recovered.
     */
    @JsonProperty("destroy")
    private boolean destroy;
    
    /**
     * Default constructor.
     */
    public DeleteOptions() {
        this.versions = new ArrayList<>();
    }
    
    /**
     * Gets the list of versions to delete.
     *
     * @return the versions
     */
    public List<Long> getVersions() {
        return versions;
    }
    
    /**
     * Sets the list of versions to delete.
     *
     * @param versions the versions
     */
    public void setVersions(List<Long> versions) {
        this.versions = versions != null ? new ArrayList<>(versions) : new ArrayList<>();
    }
    
    /**
     * Gets whether to destroy the secret permanently.
     *
     * @return true if the secret should be destroyed, false otherwise
     */
    public boolean isDestroy() {
        return destroy;
    }
    
    /**
     * Sets whether to destroy the secret permanently.
     *
     * @param destroy true if the secret should be destroyed, false otherwise
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
         * Sets the list of versions to delete.
         *
         * @param versions the versions
         * @return this builder
         */
        public Builder versions(List<Long> versions) {
            options.setVersions(versions);
            return this;
        }
        
        /**
         * Adds a version to delete.
         *
         * @param version the version
         * @return this builder
         */
        public Builder addVersion(Long version) {
            options.getVersions().add(version);
            return this;
        }
        
        /**
         * Sets whether to destroy the secret permanently.
         *
         * @param destroy true if the secret should be destroyed, false otherwise
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
