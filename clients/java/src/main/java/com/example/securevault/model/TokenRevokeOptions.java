package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Options for revoking an authentication token.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenRevokeOptions {
    @JsonProperty("token")
    private String token;
    
    @JsonProperty("orphan")
    private Boolean orphan;
    
    @JsonProperty("revoke_child")
    private Boolean revokeChild;

    /**
     * Gets the token to revoke.
     *
     * @return the token
     */
    public String getToken() {
        return token;
    }

    /**
     * Sets the token to revoke.
     *
     * @param token the token
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     * Checks if this is an orphan revocation.
     *
     * @return true for orphan revocation, false otherwise
     */
    public Boolean getOrphan() {
        return orphan;
    }

    /**
     * Sets whether this is an orphan revocation.
     *
     * @param orphan true for orphan revocation, false otherwise
     */
    public void setOrphan(Boolean orphan) {
        this.orphan = orphan;
    }

    /**
     * Checks if child tokens should be revoked.
     *
     * @return true if child tokens should be revoked, false otherwise
     */
    public Boolean getRevokeChild() {
        return revokeChild;
    }

    /**
     * Sets whether child tokens should be revoked.
     *
     * @param revokeChild true if child tokens should be revoked, false otherwise
     */
    public void setRevokeChild(Boolean revokeChild) {
        this.revokeChild = revokeChild;
    }

    /**
     * Creates a new token revoke options builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for creating token revoke options.
     */
    public static class Builder {
        private final TokenRevokeOptions options = new TokenRevokeOptions();

        /**
         * Sets the token to revoke.
         *
         * @param token the token
         * @return this builder
         */
        public Builder withToken(String token) {
            options.setToken(token);
            return this;
        }

        /**
         * Sets whether this is an orphan revocation.
         *
         * @param orphan true for orphan revocation, false otherwise
         * @return this builder
         */
        public Builder withOrphan(boolean orphan) {
            options.setOrphan(orphan);
            return this;
        }

        /**
         * Sets whether child tokens should be revoked.
         *
         * @param revokeChild true if child tokens should be revoked, false otherwise
         * @return this builder
         */
        public Builder withRevokeChild(boolean revokeChild) {
            options.setRevokeChild(revokeChild);
            return this;
        }

        /**
         * Builds the token revoke options.
         *
         * @return the token revoke options
         */
        public TokenRevokeOptions build() {
            return options;
        }
    }
}

