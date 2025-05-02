package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Represents a rule in a policy.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class PolicyRule {
    private String path;
    private List<String> capabilities;

    /**
     * Gets the path this rule applies to.
     *
     * @return the path
     */
    public String getPath() {
        return path;
    }

    /**
     * Sets the path this rule applies to.
     *
     * @param path the path
     */
    public void setPath(String path) {
        this.path = path;
    }

    /**
     * Gets the capabilities allowed on this path.
     *
     * @return the capabilities
     */
    public List<String> getCapabilities() {
        return capabilities;
    }

    /**
     * Sets the capabilities allowed on this path.
     *
     * @param capabilities the capabilities
     */
    public void setCapabilities(List<String> capabilities) {
        this.capabilities = capabilities;
    }

    /**
     * Creates a new rule builder.
     *
     * @return a new rule builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for creating policy rules.
     */
    public static class Builder {
        private final PolicyRule rule = new PolicyRule();

        /**
         * Sets the path this rule applies to.
         *
         * @param path the path
         * @return this builder
         */
        public Builder path(String path) {
            rule.setPath(path);
            return this;
        }

        /**
         * Sets the capabilities allowed on this path.
         *
         * @param capabilities the capabilities
         * @return this builder
         */
        public Builder capabilities(List<String> capabilities) {
            rule.setCapabilities(capabilities);
            return this;
        }

        /**
         * Builds the policy rule.
         *
         * @return the policy rule
         */
        public PolicyRule build() {
            return rule;
        }
    }
}
