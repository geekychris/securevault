package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Response from token lookup operation.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenLookupResponse {
    @JsonProperty("id")
    private String id;
    
    @JsonProperty("accessor")
    private String accessor;
    
    @JsonProperty("policies")
    private List<String> policies;
    
    @JsonProperty("path")
    private String path;
    
    @JsonProperty("meta")
    private Map<String, String> metadata;
    
    @JsonProperty("display_name")
    private String displayName;
    
    @JsonProperty("num_uses")
    private Integer numUses;
    
    @JsonProperty("creation_time")
    private Instant creationTime;
    
    @JsonProperty("expire_time")
    private Instant expireTime;
    
    @JsonProperty("ttl")
    private Long ttl;
    
    @JsonProperty("orphan")
    private Boolean orphan;
    
    @JsonProperty("renewable")
    private Boolean renewable;
    
    @JsonProperty("entity_id")
    private String entityId;
    
    @JsonProperty("type")
    private String type;

    /**
     * Gets the token ID.
     *
     * @return the token ID
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the token ID.
     *
     * @param id the token ID
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Gets the token accessor.
     *
     * @return the token accessor
     */
    public String getAccessor() {
        return accessor;
    }

    /**
     * Sets the token accessor.
     *
     * @param accessor the token accessor
     */
    public void setAccessor(String accessor) {
        this.accessor = accessor;
    }

    /**
     * Gets the policies associated with the token.
     *
     * @return the policies
     */
    public List<String> getPolicies() {
        return policies;
    }

    /**
     * Sets the policies associated with the token.
     *
     * @param policies the policies
     */
    public void setPolicies(List<String> policies) {
        this.policies = policies;
    }

    /**
     * Gets the path where the token was created.
     *
     * @return the path
     */
    public String getPath() {
        return path;
    }

    /**
     * Sets the path where the token was created.
     *
     * @param path the path
     */
    public void setPath(String path) {
        this.path = path;
    }

    /**
     * Gets the metadata associated with the token.
     *
     * @return the metadata
     */
    public Map<String, String> getMetadata() {
        return metadata;
    }

    /**
     * Sets the metadata associated with the token.
     *
     * @param metadata the metadata
     */
    public void setMetadata(Map<String, String> metadata) {
        this.metadata = metadata;
    }

    /**
     * Gets the display name of the token.
     *
     * @return the display name
     */
    public String getDisplayName() {
        return displayName;
    }

    /**
     * Sets the display name of the token.
     *
     * @param displayName the display name
     */
    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    /**
     * Gets the number of uses allowed for the token.
     *
     * @return the number of uses
     */
    public Integer getNumUses() {
        return numUses;
    }

    /**
     * Sets the number of uses allowed for the token.
     *
     * @param numUses the number of uses
     */
    public void setNumUses(Integer numUses) {
        this.numUses = numUses;
    }

    /**
     * Gets the creation time of the token.
     *
     * @return the creation time
     */
    public Instant getCreationTime() {
        return creationTime;
    }

    /**
     * Sets the creation time of the token.
     *
     * @param creationTime the creation time
     */
    public void setCreationTime(Instant creationTime) {
        this.creationTime = creationTime;
    }

    /**
     * Gets the expiration time of the token.
     *
     * @return the expiration time
     */
    public Instant getExpireTime() {
        return expireTime;
    }

    /**
     * Sets the expiration time of the token.
     *
     * @param expireTime the expiration time
     */
    public void setExpireTime(Instant expireTime) {
        this.expireTime = expireTime;
    }

    /**
     * Gets the time-to-live (TTL) of the token in seconds.
     *
     * @return the TTL in seconds
     */
    public Long getTtl() {
        return ttl;
    }

    /**
     * Sets the time-to-live (TTL) of the token in seconds.
     *
     * @param ttl the TTL in seconds
     */
    public void setTtl(Long ttl) {
        this.ttl = ttl;
    }

    /**
     * Checks if the token is an orphan.
     *
     * @return true if the token is an orphan, false otherwise
     */
    public Boolean getOrphan() {
        return orphan;
    }

    /**
     * Sets whether the token is an orphan.
     *
     * @param orphan true if the token is an orphan, false otherwise
     */
    public void setOrphan(Boolean orphan) {
        this.orphan = orphan;
    }

    /**
     * Checks if the token is renewable.
     *
     * @return true if the token is renewable, false otherwise
     */
    public Boolean getRenewable() {
        return renewable;
    }

    /**
     * Sets whether the token is renewable.
     *
     * @param renewable true if the token is renewable, false otherwise
     */
    public void setRenewable(Boolean renewable) {
        this.renewable = renewable;
    }

    /**
     * Gets the entity ID associated with the token.
     *
     * @return the entity ID
     */
    public String getEntityId() {
        return entityId;
    }

    /**
     * Sets the entity ID associated with the token.
     *
     * @param entityId the entity ID
     */
    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }

    /**
     * Gets the type of token.
     *
     * @return the token type
     */
    public String getType() {
        return type;
    }

    /**
     * Sets the type of token.
     *
     * @param type the token type
     */
    public void setType(String type) {
        this.type = type;
    }
}

