package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a SecureVault policy.
 * Policies define access control rules for SecureVault paths.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class Policy {
    /**
     * The name of the policy.
     */
    @JsonProperty("name")
    private String name;
    
    /**
     * The description of the policy.
     */
    @JsonProperty("description")
    private String description;
    
    /**
     * The path to apply the policy to.
     */
    private String path;
    
    /**
     * The capabilities allowed by this policy.
     */
    private List<String> capabilities;
    
    /**
     * The policy rules.
     */
    @JsonProperty("rules")
    private List<PolicyRule> rules;
    
    /**
     * Default constructor.
     */
    public Policy() {
        this.rules = new ArrayList<>();
    }
    
    /**
     * Gets the name of the policy.
     *
     * @return the policy name
     */
    public String getName() {
        return name;
    }
    
    /**
     * Sets the name of the policy.
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
     * Gets the path for this policy.
     *
     * @return the path
     */
    public String getPath() {
        return path;
    }
    
    /**
     * Sets the path for this policy.
     *
     * @param path the path
     */
    public void setPath(String path) {
        this.path = path;
        
        // Create a rule for this path if capabilities are already set
        if (path != null && capabilities != null) {
            addRule(path, capabilities);
        }
    }
    
    /**
     * Gets the capabilities allowed by this policy.
     *
     * @return the list of capabilities
     */
    public List<String> getCapabilities() {
        return capabilities;
    }
    
    /**
     * Sets the capabilities allowed by this policy.
     *
     * @param capabilities the list of capabilities
     */
    public void setCapabilities(List<String> capabilities) {
        this.capabilities = capabilities;
        
        // Create a rule for this capability if path is already set
        if (path != null && capabilities != null) {
            addRule(path, capabilities);
        }
    }
    
    /**
     * Gets the policy rules.
     *
     * @return the rules
     */
    public List<PolicyRule> getRules() {
        return rules;
    }
    
    /**
     * Sets the policy rules.
     *
     * @param rules the rules
     */
    public void setRules(List<PolicyRule> rules) {
        this.rules = rules;
    }
    
    /**
     * Adds a rule to the policy.
     *
     * @param path the path for the rule
     * @param capabilities the capabilities allowed for the path
     */
    public void addRule(String path, List<String> capabilities) {
        // Check if rule for this path already exists
        PolicyRule existingRule = rules.stream()
                .filter(rule -> rule.getPath().equals(path))
                .findFirst()
                .orElse(null);
        
        if (existingRule != null) {
            // Update existing rule
            existingRule.setCapabilities(capabilities);
        } else {
            // Create new rule
            PolicyRule rule = new PolicyRule();
            rule.setPath(path);
            rule.setCapabilities(capabilities);
            rules.add(rule);
        }
    }
    
    /**
     * Creates a new builder for Policy.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for creating Policy instances.
     */
    public static class Builder {
        private final Policy policy;
        
        /**
         * Creates a new builder.
         */
        public Builder() {
            this.policy = new Policy();
        }
        
        /**
         * Sets the policy name.
         *
         * @param name the policy name
         * @return the builder
         */
        public Builder name(String name) {
            policy.setName(name);
            return this;
        }
        
        /**
         * Sets the description for the policy.
         *
         * @param description the description
         * @return the builder
         */
        public Builder description(String description) {
            policy.setDescription(description);
            return this;
        }
        
        /**
         * Sets the path for the policy.
         *
         * @param path the path
         * @return the builder
         */
        public Builder path(String path) {
            policy.setPath(path);
            return this;
        }
        
        /**
         * Sets the capabilities for the policy.
         *
         * @param capabilities the capabilities
         * @return the builder
         */
        public Builder capabilities(List<String> capabilities) {
            policy.setCapabilities(capabilities);
            return this;
        }
        
        /**
         * Adds a rule to the policy.
         *
         * @param path the path for the rule
         * @param capabilities the capabilities allowed for the path
         * @return the builder
         */
        public Builder rule(String path, List<String> capabilities) {
            policy.addRule(path, capabilities);
            return this;
        }
        
        /**
         * Builds the policy.
         *
         * @return the built policy
         */
        public Policy build() {
            return policy;
        }
    }
}
