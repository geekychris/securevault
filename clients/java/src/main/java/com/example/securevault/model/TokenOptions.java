package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

/**
 * Options for creating an authentication token.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenOptions {
    private List<String> policyIds;
    private String ttl;

    /**
     * Gets the policy IDs to associate with the token.
     *
     * @return the policy IDs
     */
    public List<String> getPolicyIds() {
        return policyIds;
    }

    /**
     * Sets the policy IDs to associate with the token.
     *
     * @param policyIds the policy IDs
     */
    public void setPolicyIds(List<String> policyIds) {
        this.policyIds = policyIds;
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
     * Creates a new token options builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for creating token options.
     */
    public static class Builder {
        private final TokenOptions options = new TokenOptions();

        /**
         * Sets the policy IDs to associate with the token.
         *
         * @param policyIds the policy IDs
         * @return this builder
         */
        public Builder policyIds(List<String> policyIds) {
            options.setPolicyIds(policyIds);
            return this;
        }

        /**
         * Sets the TTL for the token.
         *
         * @param ttl the TTL (e.g. "1h", "30m")
         * @return this builder
         */
        public Builder ttl(String ttl) {
            options.setTtl(ttl);
            return this;
        }

        /**
         * Builds the token options.
         *
         * @return the token options
         */
        public TokenOptions build() {
            return options;
        }
    }
}

