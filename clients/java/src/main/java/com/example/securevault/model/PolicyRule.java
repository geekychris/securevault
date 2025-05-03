package com.example.securevault.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a rule within a SecureVault policy.
 * Each rule defines the capabilities allowed for a specific path.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PolicyRule {
    /**
     * The path this rule applies to.
     */
    @JsonProperty("path")
    private String path;
    
    /**
     * The capabilities granted for this path.
     */
    @JsonProperty("capabilities")
    private List<String> capabilities;
    
    /**
     * Default constructor.
     */
    public PolicyRule() {
        this.capabilities = new ArrayList<>();
    }
    
    /**
     * Creates a new rule with path and capabilities.
     *
     * @param path the path this rule applies to
     * @param capabilities the capabilities allowed for this path
     */
    public PolicyRule(String path, List<String> capabilities) {
        this.path = path;
        this.capabilities = capabilities != null ? new ArrayList<>(capabilities) : new ArrayList<>();
    }
    
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
     * Gets the capabilities granted for this path.
     *
     * @return the capabilities
     */
    public List<String> getCapabilities() {
        return capabilities;
    }
    
    /**
     * Sets the capabilities granted for this path.
     *
     * @param capabilities the capabilities
     */
    public void setCapabilities(List<String> capabilities) {
        this.capabilities = capabilities != null ? new ArrayList<>(capabilities) : new ArrayList<>();
    }
    
    /**
     * Adds a capability to this rule.
     *
     * @param capability the capability to add
     */
    public void addCapability(String capability) {
        if (capability != null && !capabilities.contains(capability)) {
            capabilities.add(capability);
        }
    }
    
    /**
     * Creates a new builder for PolicyRule.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Builder for creating PolicyRule instances.
     */
    public static class Builder {
        private final PolicyRule rule;
        
        /**
         * Creates a new builder.
         */
        public Builder() {
            this.rule = new PolicyRule();
        }
        
        /**
         * Sets the path for the rule.
         *
         * @param path the path
         * @return the builder
         */
        public Builder path(String path) {
            rule.setPath(path);
            return this;
        }
        
        /**
         * Sets the capabilities for the rule.
         *
         * @param capabilities the capabilities
         * @return the builder
         */
        public Builder capabilities(List<String> capabilities) {
            rule.setCapabilities(capabilities);
            return this;
        }
        
        /**
         * Adds a capability to the rule.
         *
         * @param capability the capability to add
         * @return the builder
         */
        public Builder capability(String capability) {
            rule.addCapability(capability);
            return this;
        }
        
        /**
         * Builds the rule.
         *
         * @return the built rule
         */
        public PolicyRule build() {
            return rule;
        }
    }
}
