package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Response from token creation or renewal operation.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenResponse {
    @JsonProperty("token_id")
    private String tokenId;
    
    @JsonProperty("policies")
    private List<String> policies;
    
    @JsonProperty("creation_time")
    private Instant creationTime;
    
    @JsonProperty("expiration_time")
    private Instant expirationTime;
    
    @JsonProperty("renewable")
    private boolean renewable;
    
    @JsonProperty("display_name")
    private String displayName;
    
    @JsonProperty("entity_id")
    private String entityId;
    
    @JsonProperty("metadata")
    private Map<String, String> metadata;
    
    @JsonProperty("num_uses")
    private int numUses;
    
    /**
     * Gets the token ID.
     *
     * @return the token ID
     */
    public String getTokenId() {
        return tokenId;
    }

    /**
     * Sets the token ID.
     *
     * @param tokenId the token ID
     */
    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
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
    public Instant getExpirationTime() {
        return expirationTime;
    }

    /**
     * Sets the expiration time of the token.
     *
     * @param expirationTime the expiration time
     */
    public void setExpirationTime(Instant expirationTime) {
        this.expirationTime = expirationTime;
    }

    /**
     * Checks if the token is renewable.
     *
     * @return true if the token is renewable, false otherwise
     */
    public boolean isRenewable() {
        return renewable;
    }

    /**
     * Sets whether the token is renewable.
     *
     * @param renewable true if the token is renewable, false otherwise
     */
    public void setRenewable(boolean renewable) {
        this.renewable = renewable;
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
     * Gets the number of uses allowed for the token.
     *
     * @return the number of uses
     */
    public int getNumUses() {
        return numUses;
    }

    /**
     * Sets the number of uses allowed for the token.
     *
     * @param numUses the number of uses
     */
    public void setNumUses(int numUses) {
        this.numUses = numUses;
    }
}

