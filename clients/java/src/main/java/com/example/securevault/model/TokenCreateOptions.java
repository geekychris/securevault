package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Options for creating an authentication token.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenCreateOptions {
    @JsonProperty("policies")
    private List<String> policies;
    
    @JsonProperty("ttl")
    private String ttl;
    
    @JsonProperty("display_name")
    private String displayName;
    
    @JsonProperty("renewable")
    private Boolean renewable;
    
    @JsonProperty("metadata")
    private Map<String, String> metadata;
    
    @JsonProperty("no_parent")
    private Boolean noParent;
    
    @JsonProperty("num_uses")
    private Integer numUses;

    /**
     * Gets the policy names to associate with the token.
     *
     * @return the policy names
     */
    public List<String> getPolicies() {
        return policies;
    }

    /**
     * Sets the policy names to associate with the token.
     *
     * @param policies the policy names
     */
    public void setPolicies(List<String> policies) {
        this.policies = policies;
    }

    /**
     * Gets the TTL for the token.
     *
     * @return the TTL
     */
    public String getTtl() {
        return ttl;
    }

    /**
     * Sets the TTL for the token.
     *
     * @param ttl the TTL
     */
    public void setTtl(String ttl) {
        this.ttl = ttl;
    }

    /**
     * Gets the display name for the token.
     *
     * @return the display name
     */
    public String getDisplayName() {
        return displayName;
    }

    /**
     * Sets the display name for the token.
     *
     * @param displayName the display name
     */
    public void setDisplayName(String displayName) {
        this.displayName = displayName;
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
     * Checks if the token has no parent.
     *
     * @return true if the token has no parent, false otherwise
     */
    public Boolean getNoParent() {
        return noParent;
    }

    /**
     * Sets whether the token has no parent.
     *
     * @param noParent true if the token has no parent, false otherwise
     */
    public void setNoParent(Boolean noParent) {
        this.noParent = noParent;
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
     * Creates a new token create options builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for creating token create options.
     */
    public static class Builder {
        private final TokenCreateOptions options = new TokenCreateOptions();

        /**
         * Sets the policy names to associate with the token.
         *
         * @param policies the policy names
         * @return this builder
         */
        public Builder withPolicies(List<String> policies) {
            options.setPolicies(policies);
            return this;
        }

        /**
         * Sets the TTL for the token.
         *
         * @param ttl the TTL as a string (e.g. "1h", "30m")
         * @return this builder
         */
        public Builder withTtl(String ttl) {
            options.setTtl(ttl);
            return this;
        }

        /**
         * Sets the TTL for the token.
         *
         * @param duration the TTL as a Duration
         * @return this builder
         */
        public Builder withTtl(Duration duration) {
            long seconds = duration.getSeconds();
            options.setTtl(seconds + "s");
            return this;
        }

        /**
         * Sets the display name for the token.
         *
         * @param displayName the display name
         * @return this builder
         */
        public Builder withDisplayName(String displayName) {
            options.setDisplayName(displayName);
            return this;
        }

        /**
         * Sets whether the token is renewable.
         *
         * @param renewable true if the token is renewable, false otherwise
         * @return this builder
         */
        public Builder withRenewable(boolean renewable) {
            options.setRenewable(renewable);
            return this;
        }

        /**
         * Sets the metadata associated with the token.
         *
         * @param metadata the metadata
         * @return this builder
         */
        public Builder withMetadata(Map<String, String> metadata) {
            options.setMetadata(metadata);
            return this;
        }

        /**
         * Sets whether the token has no parent.
         *
         * @param noParent true if the token has no parent, false otherwise
         * @return this builder
         */
        public Builder withNoParent(boolean noParent) {
            options.setNoParent(noParent);
            return this;
        }

        /**
         * Sets the number of uses allowed for the token.
         *
         * @param numUses the number of uses
         * @return this builder
         */
        public Builder withNumUses(int numUses) {
            options.setNumUses(numUses);
            return this;
        }

        /**
         * Builds the token create options.
         *
         * @return the token create options
         */
        public TokenCreateOptions build() {
            return options;
        }
    }
}

