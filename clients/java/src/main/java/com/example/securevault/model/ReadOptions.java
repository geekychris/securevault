package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Options for reading secrets from the vault.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ReadOptions {
    /**
     * The version of the secret to read.
     * If not specified, the latest version is returned.
     */
    @JsonProperty("version")
    private Long version;
    
    /**
     * Default constructor.
     */
    public ReadOptions() {
    }
    
    /**
     * Gets the version of the secret to read.
     *
     * @return the version
     */
    public Long getVersion() {
        return version;
    }
    
    /**
     * Sets the version of the secret to read.
     *
     * @param version the version
     */
    public void setVersion(Long version) {
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
        public Builder version(Long version) {
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
