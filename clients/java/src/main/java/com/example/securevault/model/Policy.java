package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Represents an access policy in SecureVault.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Policy {
    private String name;
    private String description;
    private List<PolicyRule> rules;

    /**
     * Gets the policy name.
     *
     * @return the policy name
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the policy name.
     *
     * @param name the policy name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Gets the policy description.
     *
     * @return the policy description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets the policy description.
     *
     * @param description the policy description
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Gets the policy rules.
     *
     * @return the policy rules
     */
    public List<PolicyRule> getRules() {
        return rules;
    }

    /**
     * Sets the policy rules.
     *
     * @param rules the policy rules
     */
    public void setRules(List<PolicyRule> rules) {
        this.rules = rules;
    }

    /**
     * Creates a new policy builder.
     *
     * @return a new policy builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for creating policies.
     */
    public static class Builder {
        private final Policy policy = new Policy();

        /**
         * Sets the policy name.
         *
         * @param name the policy name
         * @return this builder
         */
        public Builder name(String name) {
            policy.setName(name);
            return this;
        }

        /**
         * Sets the policy description.
         *
         * @param description the policy description
         * @return this builder
         */
        public Builder description(String description) {
            policy.setDescription(description);
            return this;
        }

        /**
         * Sets the policy rules.
         *
         * @param rules the policy rules
         * @return this builder
         */
        public Builder rules(List<PolicyRule> rules) {
            policy.setRules(rules);
            return this;
        }

        /**
         * Builds the policy.
         *
         * @return the policy
         */
        public Policy build() {
            return policy;
        }
    }
}
