package com.example.securevault;

import com.example.securevault.exception.SecureVaultException;
import com.example.securevault.exception.SecureVaultForbiddenException;
import com.example.securevault.exception.SecureVaultNotFoundException;
import com.example.securevault.exception.SecureVaultUnauthorizedException;
import com.example.securevault.model.*;
import com.example.securevault.model.ClientConfig;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.classic.methods.*;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.util.Timeout;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Client for interacting with the SecureVault API.
 */
public class SecureVaultClient implements AutoCloseable {
    /**
     * Creates a new builder for SecureVaultClient.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
    /**
     * API version to use for all requests.
     */
    private static final String API_VERSION = "v1";
    
    /**
     * The HTTP client for making API requests.
     */
    private final CloseableHttpClient httpClient;
    
    /**
     * The client configuration.
     */
    private final ClientConfig config;
    
    /**
     * The authentication token to use for API requests.
     */
    private String token;
    
    /**
     * The JSON object mapper.
     */
    private final ObjectMapper objectMapper;
    
    /**
     * Creates a new client with the given configuration.
     *
     * @param config the client configuration
     */
    public SecureVaultClient(ClientConfig config) {
        this.config = config;
        this.token = config.getToken();
        this.objectMapper = new ObjectMapper();
        
        PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
        connectionManager.setMaxTotal(config.getMaxConnections());
        connectionManager.setDefaultMaxPerRoute(config.getMaxConnectionsPerRoute());
        
        RequestConfig requestConfig = RequestConfig.custom()
                .setResponseTimeout(Timeout.of(config.getRequestTimeoutMillis(), TimeUnit.MILLISECONDS))
                .setConnectTimeout(Timeout.of(config.getConnectTimeoutMillis(), TimeUnit.MILLISECONDS))
                .build();
        
        this.httpClient = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setDefaultRequestConfig(requestConfig)
                .build();
    }

    /**
     * Writes a secret to the vault.
     *
     * @param path   the path to the secret
     * @param secret the secret data to write
     * @return true if the operation was successful
     * @throws SecureVaultException if an error occurs
     */
    public boolean writeSecret(String path, Map<String, Object> secret) throws SecureVaultException {
        return writeSecret(path, secret, null);
    }
    
    /**
     * Writes a secret to the vault with options.
     *
     * @param path    the path to the secret
     * @param secret  the secret data to write
     * @param options options for the write operation
     * @return true if the operation was successful
     * @throws SecureVaultException if an error occurs
     */
    public boolean writeSecret(String path, Map<String, Object> secret, com.example.securevault.model.WriteOptions options) throws SecureVaultException {
        try {
            StringBuilder uriBuilder = new StringBuilder(buildUri("/secret/" + path));
            
            if (options != null) {
                List<String> queryParams = new ArrayList<>();
                
                if (options.getCas() != null) {
                    queryParams.add("cas=" + options.getCas());
                }
                
                if (!queryParams.isEmpty()) {
                    uriBuilder.append("?").append(String.join("&", queryParams));
                }
            }
            
            HttpPost request = new HttpPost(uriBuilder.toString());
            request.setEntity(createJsonEntity(secret));
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_NO_CONTENT || response.getCode() == HttpStatus.SC_OK) {
                    return true;
                } else {
                    handleErrorResponse(response);
                    return false;
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to write secret", e);
        }
    }

    /**
     * Reads a secret from the vault.
     *
     * @param path the path to the secret
     * @return the secret data
     * @throws SecureVaultException if an error occurs
     */
    public Map<String, Object> readSecret(String path) throws SecureVaultException {
        return readSecret(path, (Long) null);
    }
    
    /**
     * Reads a secret from the vault.
     *
     * @param path    the path to the secret
     * @param version the version of the secret to read (optional)
     * @return the secret data
     * @throws SecureVaultException if an error occurs
     */
    public Map<String, Object> readSecret(String path, Long version) throws SecureVaultException {
        try {
            StringBuilder uriBuilder = new StringBuilder(buildUri("/secret/" + path));
            
            if (version != null) {
                uriBuilder.append("?version=").append(version);
            }
            
            HttpGet request = new HttpGet(uriBuilder.toString());
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_OK) {
                    String json = EntityUtils.toString(response.getEntity());
                    return objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {});
                } else {
                    handleErrorResponse(response);
                    return null;
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to read secret", e);
        }
    }
    /**
     * Deletes a secret from the vault.
     *
     * @param path the path to the secret
     * @return true if the operation was successful
     * @throws SecureVaultException if an error occurs
     */
    public boolean deleteSecret(String path) throws SecureVaultException {
        return deleteSecret(path, null);
    }

    /**
     * Deletes a secret from the vault with options.
     *
     * @param path    the path to the secret
     * @param options options for the delete operation
     * @return true if the operation was successful
     * @throws SecureVaultException if an error occurs
     */
    public boolean deleteSecret(String path, com.example.securevault.model.DeleteOptions options) throws SecureVaultException {
        try {
            StringBuilder uriBuilder = new StringBuilder(buildUri("/secret/" + path));
            
            if (options != null) {
                List<String> queryParams = new ArrayList<>();
                
                if (options.isDestroy()) {
                    queryParams.add("destroy=true");
                }
                
                if (options.getVersions() != null && !options.getVersions().isEmpty()) {
                    String versions = String.join(",", 
                            options.getVersions().stream().map(Object::toString).toList());
                    queryParams.add("versions=" + versions);
                }
                
                if (!queryParams.isEmpty()) {
                    uriBuilder.append("?").append(String.join("&", queryParams));
                }
            }
            
            HttpDelete request = new HttpDelete(uriBuilder.toString());
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_NO_CONTENT || response.getCode() == HttpStatus.SC_OK) {
                    return true;
                } else {
                    handleErrorResponse(response);
                    return false;
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to delete secret", e);
        }
    }

    /**
     * Lists secrets under a path.
     *
     * @param path the path to list secrets under
     * @return a list of secret paths
     * @throws SecureVaultException if an error occurs
     */
    public List<String> listSecrets(String path) throws SecureVaultException {
        return listSecrets(path, null);
    }

    /**
     * Lists secrets under a path with options.
     *
     * @param path    the path to list secrets under
     * @param options options for the list operation
     * @return a list of secret paths
     * @throws SecureVaultException if an error occurs
     */
    public List<String> listSecrets(String path, com.example.securevault.model.ListOptions options) throws SecureVaultException {
        try {
            // Normalize path
            if (!path.isEmpty() && !path.endsWith("/")) {
                path += "/";
            }
            
            StringBuilder uriBuilder = new StringBuilder(buildUri("/secret/" + path));
            uriBuilder.append("?list=true");
            
            if (options != null && options.isRecursive()) {
                uriBuilder.append("&recursive=true");
            }
            
            HttpGet request = new HttpGet(uriBuilder.toString());
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_OK) {
                    String json = EntityUtils.toString(response.getEntity());
                    Map<String, List<String>> result = objectMapper.readValue(json, 
                            new TypeReference<Map<String, List<String>>>() {});
                    return result.getOrDefault("keys", Collections.emptyList());
                } else {
                    handleErrorResponse(response);
                    return Collections.emptyList();
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to list secrets", e);
        }
    }

    /**
     * Gets metadata about a secret.
     *
     * @param path the path to the secret
     * @return the secret metadata
     * @throws SecureVaultException if an error occurs
     */
    public SecretMetadata getSecretMetadata(String path) throws SecureVaultException {
        try {
            String uri = buildUri("/secret/" + path + "/metadata");
            HttpGet request = new HttpGet(uri);
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_OK) {
                    String json = EntityUtils.toString(response.getEntity());
                    return objectMapper.readValue(json, SecretMetadata.class);
                } else {
                    handleErrorResponse(response);
                    return null;
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to get secret metadata", e);
        }
    }

    /**
     * Creates a new policy.
     *
     * @param policy the policy to create
     * @return true if the operation was successful
     * @throws SecureVaultException if an error occurs
     */
    public boolean createPolicy(Policy policy) throws SecureVaultException {
        try {
            String uri = buildUri("/policies");
            HttpPost request = new HttpPost(uri);
            request.setEntity(createJsonEntity(policy));
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_NO_CONTENT || response.getCode() == HttpStatus.SC_OK) {
                    return true;
                } else {
                    handleErrorResponse(response);
                    return false;
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to create policy", e);
        }
    }

    /**
     * Gets a policy by name.
     *
     * @param name the name of the policy
     * @return the policy
     * @throws SecureVaultException if an error occurs
     */
    public Policy getPolicy(String name) throws SecureVaultException {
        try {
            String uri = buildUri("/policies/" + name);
            HttpGet request = new HttpGet(uri);
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_OK) {
                    String json = EntityUtils.toString(response.getEntity());
                    return objectMapper.readValue(json, Policy.class);
                } else {
                    handleErrorResponse(response);
                    return null;
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to get policy", e);
        }
    }

    /**
     * Updates an existing policy.
     *
     * @param policy the policy to update
     * @return true if the operation was successful
     * @throws SecureVaultException if an error occurs
     */
    public boolean updatePolicy(Policy policy) throws SecureVaultException {
        try {
            String uri = buildUri("/policies/" + policy.getName());
            HttpPut request = new HttpPut(uri);
            request.setEntity(createJsonEntity(policy));
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_NO_CONTENT || response.getCode() == HttpStatus.SC_OK) {
                    return true;
                } else {
                    handleErrorResponse(response);
                    return false;
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to update policy", e);
        }
    }

    /**
     * Deletes a policy.
     *
     * @param name the name of the policy to delete
     * @return true if the operation was successful
     * @throws SecureVaultException if an error occurs
     */
    public boolean deletePolicy(String name) throws SecureVaultException {
        try {
            String uri = buildUri("/policies/" + name);
            HttpDelete request = new HttpDelete(uri);
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_NO_CONTENT || response.getCode() == HttpStatus.SC_OK) {
                    return true;
                } else {
                    handleErrorResponse(response);
                    return false;
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to delete policy", e);
        }
    }

    /**
     * Lists all policies.
     *
     * @return a list of policy names
     * @throws SecureVaultException if an error occurs
     */
    public List<String> listPolicies() throws SecureVaultException {
        try {
            String uri = buildUri("/policies");
            HttpGet request = new HttpGet(uri);
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_OK) {
                    String json = EntityUtils.toString(response.getEntity());
                    Map<String, List<String>> result = objectMapper.readValue(json, 
                            new TypeReference<Map<String, List<String>>>() {});
                    return result.getOrDefault("policies", Collections.emptyList());
                } else {
                    handleErrorResponse(response);
                    return Collections.emptyList();
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to list policies", e);
        }
    }

    /**
     * Creates a new authentication token.
     *
     * @param options options for creating the token
     * @return the token response
     * @throws SecureVaultException if an error occurs
     */
    public TokenResponse createToken(TokenCreateOptions options) throws SecureVaultException {
        try {
            String uri = buildUri("/auth/token/create");
            HttpPost request = new HttpPost(uri);
            request.setEntity(createJsonEntity(options));
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_OK) {
                    String json = EntityUtils.toString(response.getEntity());
                    return objectMapper.readValue(json, TokenResponse.class);
                } else {
                    handleErrorResponse(response);
                    return null;
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to create token", e);
        }
    }

    /**
     * Renews an authentication token.
     *
     * @param options options for renewing the token
     * @return the renewed token response
     * @throws SecureVaultException if an error occurs
     */
    public TokenResponse renewToken(TokenRenewOptions options) throws SecureVaultException {
        try {
            String uri = buildUri("/auth/token/renew");
            HttpPost request = new HttpPost(uri);
            request.setEntity(createJsonEntity(options));
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_OK) {
                    String json = EntityUtils.toString(response.getEntity());
                    return objectMapper.readValue(json, TokenResponse.class);
                } else {
                    handleErrorResponse(response);
                    return null;
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to renew token", e);
        }
    }

    /**
     * Renews the current authentication token.
     *
     * @param increment the renewal increment (e.g. "1h", "30m")
     * @return the renewed token response
     * @throws SecureVaultException if an error occurs
     */
    public TokenResponse renewSelfToken(String increment) throws SecureVaultException {
        try {
            String uri = buildUri("/auth/token/renew-self");
            HttpPost request = new HttpPost(uri);
            
            Map<String, String> requestBody = new HashMap<>();
            if (increment != null && !increment.isEmpty()) {
                requestBody.put("increment", increment);
            }
            
            request.setEntity(createJsonEntity(requestBody));
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_OK) {
                    String json = EntityUtils.toString(response.getEntity());
                    return objectMapper.readValue(json, TokenResponse.class);
                } else {
                    handleErrorResponse(response);
                    return null;
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to renew self token", e);
        }
    }

    /**
     * Looks up information about an authentication token.
     *
     * @param token the token to look up
     * @return the token lookup response
     * @throws SecureVaultException if an error occurs
     */
    public TokenLookupResponse lookupToken(String token) throws SecureVaultException {
        try {
            String uri = buildUri("/auth/token/lookup");
            HttpPost request = new HttpPost(uri);
            
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("token", token);
            
            request.setEntity(createJsonEntity(requestBody));
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_OK) {
                    String json = EntityUtils.toString(response.getEntity());
                    return objectMapper.readValue(json, TokenLookupResponse.class);
                } else {
                    handleErrorResponse(response);
                    return null;
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to look up token", e);
        }
    }

    /**
     * Looks up information about the current authentication token.
     *
     * @return the token lookup response
     * @throws SecureVaultException if an error occurs
     */
    public TokenLookupResponse lookupSelfToken() throws SecureVaultException {
        try {
            String uri = buildUri("/auth/token/lookup-self");
            HttpGet request = new HttpGet(uri);
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_OK) {
                    String json = EntityUtils.toString(response.getEntity());
                    return objectMapper.readValue(json, TokenLookupResponse.class);
                } else {
                    handleErrorResponse(response);
                    return null;
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to look up self token", e);
        }
    }

    /**
     * Revokes an authentication token.
     *
     * @param options options for revoking the token
     * @return true if the operation was successful
     * @throws SecureVaultException if an error occurs
     */
    public boolean revokeToken(TokenRevokeOptions options) throws SecureVaultException {
        try {
            StringBuilder uriBuilder = new StringBuilder(buildUri("/auth/token/revoke"));
            
            List<String> queryParams = new ArrayList<>();
            if (options.getOrphan() != null && options.getOrphan()) {
                queryParams.add("orphan=true");
            }
            
            if (options.getRevokeChild() != null && options.getRevokeChild()) {
                queryParams.add("revoke_child=true");
            }
            
            if (!queryParams.isEmpty()) {
                uriBuilder.append("?").append(String.join("&", queryParams));
            }
            
            HttpPost request = new HttpPost(uriBuilder.toString());
            
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("token", options.getToken());
            
            request.setEntity(createJsonEntity(requestBody));
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_NO_CONTENT || response.getCode() == HttpStatus.SC_OK) {
                    return true;
                } else {
                    handleErrorResponse(response);
                    return false;
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to revoke token", e);
        }
    }

    /**
     * Revokes the current authentication token.
     *
     * @return true if the operation was successful
     * @throws SecureVaultException if an error occurs
     */
    public boolean revokeSelfToken() throws SecureVaultException {
        try {
            String uri = buildUri("/auth/token/revoke-self");
            HttpPost request = new HttpPost(uri);
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_NO_CONTENT || response.getCode() == HttpStatus.SC_OK) {
                    return true;
                } else {
                    handleErrorResponse(response);
                    return false;
                }
            }
        } catch (Exception e) {
            throw new SecureVaultException("Failed to revoke self token", e);
        }
    }

    /**
     * Sets the token to use for authentication.
     *
     * @param token the token
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     * Closes the client and releases resources.
     */
    @Override
    public void close() throws IOException {
        if (httpClient != null) {
            httpClient.close();
        }
    }

    /**
     * Builds a URI for the API.
     * 
     * @param path the API path
     * @return the full API URI
     */
    /**
     * Builds a URI for the API.
     * Note that the API_VERSION is already included in the path by the SecureVault server,
     * so we don't append it here.
     * 
     * @param path the API path
     * @return the full API URI
     */
    private String buildUri(String path) {
        // Add the /v1 prefix to all API paths
        if (path.startsWith("/")) {
            // If the path already starts with a slash, just add the v1 before it
            return config.getAddress() + "/v1" + path;
        } else {
            // Otherwise add /v1/ including the slash
            return config.getAddress() + "/v1/" + path;
        }
    }

    /**
     * Creates a JSON entity from an object.
     * 
     * @param obj the object to convert to JSON
     * @return the StringEntity containing the JSON
     * @throws JsonProcessingException if the object cannot be converted to JSON
     */
    private StringEntity createJsonEntity(Object obj) throws JsonProcessingException {
        String json = objectMapper.writeValueAsString(obj);
        return new StringEntity(json, ContentType.APPLICATION_JSON);
    }

    /**
     * Executes an HTTP request with token authentication.
     * 
     * @param request the HTTP request to execute
     * @return the HTTP response
     * @throws IOException if an I/O error occurs
     */
    private CloseableHttpResponse executeRequest(HttpUriRequest request) throws IOException {
        if (token != null && !token.isEmpty()) {
            request.setHeader("X-Vault-Token", token);
        }
        return httpClient.execute(request);
    }

    /**
     * Handles error responses from the API.
     * 
     * @param response the HTTP response containing an error
     * @throws IOException if an I/O error occurs
     * @throws SecureVaultException if an API error occurs
     * @throws SecureVaultNotFoundException if the requested resource was not found
     * @throws SecureVaultUnauthorizedException if authentication is required
     * @throws SecureVaultForbiddenException if access is forbidden
     */
    private void handleErrorResponse(CloseableHttpResponse response) throws IOException {
        int statusCode = response.getCode();
        
        String errorMessage;
        try {
            String responseBody = EntityUtils.toString(response.getEntity());
            Map<String, Object> errorMap = objectMapper.readValue(responseBody, 
                    new TypeReference<Map<String, Object>>() {});
            
            // SecureVault errors can be either a string or nested error object
            Object errorObj = errorMap.get("error");
            if (errorObj instanceof String) {
                errorMessage = (String) errorObj;
            } else if (errorObj instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> errorDetails = (Map<String, Object>) errorObj;
                errorMessage = errorDetails.containsKey("message") 
                    ? errorDetails.get("message").toString() 
                    : "Unknown error details";
            } else {
                errorMessage = "Unknown error format";
            }
        } catch (Exception e) {
            errorMessage = "Status code: " + statusCode;
        }
        
        if (statusCode == HttpStatus.SC_NOT_FOUND) {
            throw new SecureVaultNotFoundException(errorMessage);
        } else if (statusCode == HttpStatus.SC_UNAUTHORIZED) {
            throw new SecureVaultUnauthorizedException(errorMessage);
        } else if (statusCode == HttpStatus.SC_FORBIDDEN) {
            throw new SecureVaultForbiddenException(errorMessage);
        } else {
            throw new SecureVaultException("API error: " + errorMessage);
        }
    }

    /**
     * Builder for creating client instances.
     */
    public static class Builder {
        private String address;
        private String token;
        private int maxConnections = 20;
        private int maxConnectionsPerRoute = 10;
        private long requestTimeoutMillis = 10_000;
        private long connectTimeoutMillis = 5_000;
        
        /**
         * Sets the server address.
         *
         * @param address the server address
         * @return the builder
         */
        public Builder address(String address) {
            this.address = address;
            return this;
        }
        
        /**
         * Sets the authentication token.
         *
         * @param token the authentication token
         * @return the builder
         */
        public Builder token(String token) {
            this.token = token;
            return this;
        }
        
        /**
         * Sets the maximum number of connections.
         *
         * @param maxConnections the maximum number of connections
         * @return the builder
         */
        public Builder maxConnections(int maxConnections) {
            this.maxConnections = maxConnections;
            return this;
        }
        
        /**
         * Sets the maximum number of connections per route.
         *
         * @param maxConnectionsPerRoute the maximum number of connections per route
         * @return the builder
         */
        public Builder maxConnectionsPerRoute(int maxConnectionsPerRoute) {
            this.maxConnectionsPerRoute = maxConnectionsPerRoute;
            return this;
        }
        
        /**
         * Sets the request timeout in milliseconds.
         *
         * @param requestTimeoutMillis the request timeout in milliseconds
         * @return the builder
         */
        public Builder requestTimeout(long requestTimeoutMillis) {
            this.requestTimeoutMillis = requestTimeoutMillis;
            return this;
        }
        
        /**
         * Sets the connect timeout in milliseconds.
         *
         * @param connectTimeoutMillis the connect timeout in milliseconds
         * @return the builder
         */
        public Builder connectTimeout(long connectTimeoutMillis) {
            this.connectTimeoutMillis = connectTimeoutMillis;
            return this;
        }
        
        /**
         * Builds the client.
         *
         * @return a new SecureVaultClient instance
         * @throws IllegalArgumentException if required configuration is missing
         */
        public SecureVaultClient build() {
            // Validate required fields
            if (address == null || address.trim().isEmpty()) {
                throw new IllegalArgumentException("Server address is required");
            }
            
            // Token validation is optional since it can be set later or obtained through authentication
            if (token != null && token.trim().isEmpty()) {
                throw new IllegalArgumentException("Token cannot be empty if provided");
            }
            
            // Validate connection settings
            if (maxConnections < 1) {
                throw new IllegalArgumentException("Maximum connections must be at least 1");
            }
            
            if (maxConnectionsPerRoute < 1) {
                throw new IllegalArgumentException("Maximum connections per route must be at least 1");
            }
            
            if (requestTimeoutMillis < 0) {
                throw new IllegalArgumentException("Request timeout cannot be negative");
            }
            
            if (connectTimeoutMillis < 0) {
                throw new IllegalArgumentException("Connect timeout cannot be negative");
            }
            ClientConfig config = new ClientConfig();
            config.setAddress(address);
            config.setToken(token);
            config.setMaxConnections(maxConnections);
            config.setMaxConnectionsPerRoute(maxConnectionsPerRoute);
            config.setRequestTimeoutMillis(requestTimeoutMillis);
            config.setConnectTimeoutMillis(connectTimeoutMillis);
            
            return new SecureVaultClient(config);
        }
    }
    // All option classes are now in the model package
}
