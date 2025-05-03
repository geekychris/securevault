package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents a secret stored in SecureVault.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class Secret {
    /**
     * The data of the secret.
     */
    @JsonProperty("data")
    private Map<String, Object> data;
    
    /**
     * The metadata of the secret.
     */
    @JsonProperty("metadata")
    private Map<String, Object> metadata;
    
    /**
     * Default constructor.
     */
    public Secret() {
        this.data = new HashMap<>();
        this.metadata = new HashMap<>();
    }
    
    /**
     * Constructor with data.
     *
     * @param data the secret data
     */
    public Secret(Map<String, Object> data) {
        this.data = data != null ? new HashMap<>(data) : new HashMap<>();
        this.metadata = new HashMap<>();
    }
    
    /**
     * Creates a new secret from the given data map.
     *
     * @param data the map containing the secret data
     * @return a new Secret instance
     */
    public static Secret fromMap(Map<String, Object> data) {
        if (data == null) {
            return new Secret();
        }
        
        Secret secret = new Secret();
        
        // If data contains a "data" field, use that as the secret data
        if (data.containsKey("data") && data.get("data") instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> secretData = (Map<String, Object>) data.get("data");
            secret.setData(secretData);
        } else {
            // Otherwise, use the entire map as the data
            secret.setData(data);
        }
        
        // If data contains a "metadata" field, use that as the metadata
        if (data.containsKey("metadata") && data.get("metadata") instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> metadata = (Map<String, Object>) data.get("metadata");
            secret.setMetadata(metadata);
        }
        
        return secret;
    }
    
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
        this.data = data != null ? new HashMap<>(data) : new HashMap<>();
    }
    
    /**
     * Gets the metadata.
     *
     * @return the metadata
     */
    public Map<String, Object> getMetadata() {
        return metadata;
    }
    
    /**
     * Sets the metadata.
     *
     * @param metadata the metadata
     */
    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata != null ? new HashMap<>(metadata) : new HashMap<>();
    }
    
    /**
     * Gets a value from the secret data.
     *
     * @param key the key
     * @return the value, or null if not found
     */
    public Object get(String key) {
        return data.get(key);
    }
    
    /**
     * Puts a value in the secret data.
     *
     * @param key the key
     * @param value the value
     */
    public void put(String key, Object value) {
        data.put(key, value);
    }
    
    /**
     * Converts the secret data to a map.
     *
     * @return the secret data as a map
     */
    public Map<String, Object> toMap() {
        return new HashMap<>(data);
    }
}
