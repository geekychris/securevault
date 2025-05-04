package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Duration;

/**
 * Options for renewing an authentication token.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenRenewOptions {
    @JsonProperty("token")
    private String token;
    
    @JsonProperty("increment")
    private String increment;

    /**
     * Gets the token to renew.
     *
     * @return the token
     */
    public String getToken() {
        return token;
    }

    /**
     * Sets the token to renew.
     *
     * @param token the token
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     * Gets the increment for the renewal.
     *
     * @return the increment
     */
    public String getIncrement() {
        return increment;
    }

    /**
     * Sets the increment for the renewal.
     *
     * @param increment the increment
     */
    public void setIncrement(String increment) {
        this.increment = increment;
    }

    /**
     * Creates a new token renew options builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for creating token renew options.
     */
    public static class Builder {
        private final TokenRenewOptions options = new TokenRenewOptions();

        /**
         * Sets the token to renew.
         *
         * @param token the token
         * @return this builder
         */
        public Builder withToken(String token) {
            options.setToken(token);
            return this;
        }

        /**
         * Sets the increment for the renewal.
         *
         * @param increment the increment as a string (e.g. "1h", "30m")
         * @return this builder
         */
        public Builder withIncrement(String increment) {
            options.setIncrement(increment);
            return this;
        }

        /**
         * Sets the increment for the renewal.
         *
         * @param duration the increment as a Duration
         * @return this builder
         */
        public Builder withIncrement(Duration duration) {
            long seconds = duration.getSeconds();
            options.setIncrement(seconds + "s");
            return this;
        }

        /**
         * Builds the token renew options.
         *
         * @return the token renew options
         */
        public TokenRenewOptions build() {
            return options;
        }
    }
}
