package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * Options for writing secrets to the vault.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class WriteOptions {
    /**
     * Custom metadata to associate with the secret.
     */
    @JsonProperty("metadata")
    private Map<String, String> metadata;
    
    /**
     * Check-And-Set parameter for optimistic concurrency control.
     * If provided, the write will only succeed if the current version matches this value.
     */
    @JsonProperty("cas")
    private Integer cas;
    
    /**
     * Default constructor.
     */
    public WriteOptions() {
    }
    
    /**
     * Gets custom metadata to associate with the secret.
     *
     * @return the metadata
     */
    public Map<String, String> getMetadata() {
        return metadata;
    }
    
    /**
     * Sets custom metadata to associate with the secret.
     *
     * @param metadata the metadata
     */
    public void setMetadata(Map<String, String> metadata) {
        this.metadata = metadata;
    }
    
    /**
     * Gets the Compare-And-Swap value for optimistic concurrency control.
     *
     * @return the CAS value
     */
    public Integer getCas() {
        return cas;
    }
    
    /**
     * Sets the Compare-And-Swap value for optimistic concurrency control.
     *
     * @param cas the CAS value
     */
    public void setCas(Integer cas) {
        this.cas = cas;
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
         * Sets custom metadata to associate with the secret.
         *
         * @param metadata the metadata
         * @return this builder
         */
        public Builder metadata(Map<String, String> metadata) {
            options.setMetadata(metadata);
            return this;
        }
        
        /**
         * Sets the Compare-And-Swap value for optimistic concurrency control.
         *
         * @param cas the CAS value
         * @return this builder
         */
        public Builder cas(Integer cas) {
            options.setCas(cas);
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
