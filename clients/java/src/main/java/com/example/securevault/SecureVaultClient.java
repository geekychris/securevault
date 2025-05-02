package com.example.securevault;

import com.example.securevault.config.ClientConfig;
import com.example.securevault.exception.SecureVaultException;
import com.example.securevault.exception.SecureVaultForbiddenException;
import com.example.securevault.exception.SecureVaultNotFoundException;
import com.example.securevault.exception.SecureVaultUnauthorizedException;
import com.example.securevault.model.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Client for interacting with the SecureVault API.
 */
public class SecureVaultClient implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(SecureVaultClient.class);
    private static final String API_VERSION = "v1";
    private static final int DEFAULT_MAX_RETRIES = 3;
    
    private final ClientConfig config;
    private final CloseableHttpClient httpClient;
    private final ObjectMapper objectMapper;
    private String token;
    private final Object tokenLock = new Object();

    /**
     * Creates a new client with the provided configuration.
     *
     * @param config the client configuration
     */
    public SecureVaultClient(ClientConfig config) {
        this.config = config;
        this.token = config.getToken();
        this.objectMapper = createObjectMapper();
        this.httpClient = createHttpClient();
    }

    /**
     * Creates an ObjectMapper with custom configuration.
     */
    private ObjectMapper createObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        // Register JavaTimeModule for handling Java 8 date/time types
        mapper.registerModule(new JavaTimeModule());
        return mapper;
    }

    /**
     * Creates a configured HTTP client.
     */
    private CloseableHttpClient createHttpClient() {
        PoolingHttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager();
        connManager.setMaxTotal(config.getMaxConnections());
        connManager.setDefaultMaxPerRoute(config.getMaxConnectionsPerRoute());
        
        RequestConfig requestConfig = RequestConfig.custom()
                .setResponseTimeout(Timeout.of(config.getRequestTimeoutMillis(), TimeUnit.MILLISECONDS))
                .setConnectTimeout(Timeout.of(config.getConnectTimeoutMillis(), TimeUnit.MILLISECONDS))
                .build();
        
        return HttpClients.custom()
                .setConnectionManager(connManager)
                .setDefaultRequestConfig(requestConfig)
                .build();
    }

    /**
     * Returns a new builder for creating a client.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Writes a secret to the vault.
     *
     * @param path the path to the secret
     * @param data the secret data to write
     * @return true if the operation was successful
     * @throws SecureVaultException if an error occurs
     */
    public boolean writeSecret(String path, Map<String, Object> data) throws SecureVaultException {
        return writeSecret(path, data, null);
    }

    /**
     * Writes a secret to the vault with options.
     *
     * @param path    the path to the secret
     * @param data    the secret data to write
     * @param options options for the write operation
     * @return true if the operation was successful
     * @throws SecureVaultException if an error occurs
     */
    public boolean writeSecret(String path, Map<String, Object> data, WriteOptions options) throws SecureVaultException {
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("data", data);
        
        if (options != null && options.getMetadata() != null) {
            requestBody.put("metadata", options.getMetadata());
        }
        
        try {
            String uri = buildUri("/secret/" + path);
            HttpPost request = new HttpPost(uri);
            request.setEntity(createJsonEntity(requestBody));
            
            try (CloseableHttpResponse response = executeRequestWithRetry(request)) {
                int statusCode = response.getCode();
                if (statusCode == HttpStatus.SC_NO_CONTENT || statusCode == HttpStatus.SC_OK) {
                    return true;
                } else {
                    handleErrorResponse(response);
                    return false;
                }
            }
        } catch (SecureVaultException e) {
            throw e;
        } catch (Exception e) {
            throw new SecureVaultException("Failed to write secret: " + e.getMessage(), e);
        }
    }

    /**
     * Reads the latest version of a secret from the vault.
     *
     * @

package com.example.securevault;

import com.example.securevault.config.ClientConfig;
import com.example.securevault.exception.SecureVaultException;
import com.example.securevault.model.*;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Client for interacting with the SecureVault API.
 */
public class SecureVaultClient implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(SecureVaultClient.class);
    private static final String API_VERSION = "v1";
    
    private final ClientConfig config;
    private final CloseableHttpClient httpClient;
    private final ObjectMapper objectMapper;
    private String token;

    /**
     * Creates a new client with the provided configuration.
     *
     * @param config the client configuration
     */
    public SecureVaultClient(ClientConfig config) {
        this.config = config;
        this.token = config.getToken();
        this.objectMapper = createObjectMapper();
        this.httpClient = createHttpClient();
    }

    /**
     * Creates an ObjectMapper with custom configuration.
     */
    private ObjectMapper createObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.findAndRegisterModules(); // For Java 8 date/time types
        return mapper;
    }

    /**
     * Creates a configured HTTP client.
     */
    private CloseableHttpClient createHttpClient() {
        PoolingHttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager();
        connManager.setMaxTotal(config.getMaxConnections());
        connManager.setDefaultMaxPerRoute(config.getMaxConnectionsPerRoute());
        
        RequestConfig requestConfig = RequestConfig.custom()
                .setResponseTimeout(Timeout.of(config.getRequestTimeoutMillis(), TimeUnit.MILLISECONDS))
                .setConnectTimeout(Timeout.of(config.getConnectTimeoutMillis(), TimeUnit.MILLISECONDS))
                .build();
        
        return HttpClients.custom()
                .setConnectionManager(connManager)
                .setDefaultRequestConfig(requestConfig)
                .build();
    }

    /**
     * Returns a new builder for creating a client.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Writes a secret to the vault.
     *
     * @param path the path to the secret
     * @param data the secret data to write
     * @return true if the operation was successful
     * @throws SecureVaultException if an error occurs
     */
    public boolean writeSecret(String path, Map<String, Object> data) throws SecureVaultException {
        return writeSecret(path, data, null);
    }

    /**
     * Writes a secret to the vault with options.
     *
     * @param path    the path to the secret
     * @param data    the secret data to write
     * @param options options for the write operation
     * @return true if the operation was successful
     * @throws SecureVaultException if an error occurs
     */
    public boolean writeSecret(String path, Map<String, Object> data, WriteOptions options) throws SecureVaultException {
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("data", data);
        
        if (options != null && options.getMetadata() != null) {
            requestBody.put("metadata", options.getMetadata());
        }
        
        try {
            String uri = buildUri("/secret/" + path);
            HttpPost request = new HttpPost(uri);
            request.setEntity(createJsonEntity(requestBody));
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                int statusCode = response.getCode();
                if (statusCode == HttpStatus.SC_NO_CONTENT || statusCode == HttpStatus.SC_OK) {
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
     * Reads the latest version of a secret from the vault.
     *
     * @param path the path to the secret
     * @return the secret
     * @throws SecureVaultException if an error occurs
     */
    public Secret readSecret(String path) throws SecureVaultException {
        return readSecret(path, null);
    }

    /**
     * Reads a specific version of a secret from the vault.
     *
     * @param path    the path to the secret
     * @param options options for the read operation
     * @return the secret
     * @throws SecureVaultException if an error occurs
     */
    public Secret readSecret(String path, ReadOptions options) throws SecureVaultException {
        try {
            String uri;
            if (options != null && options.getVersion() > 0) {
                uri = buildUri(String.format("/secret/%s/versions/%d", path, options.getVersion()));
            } else {
                uri = buildUri("/secret/" + path);
            }
            
            HttpGet request = new HttpGet(uri);
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_OK) {
                    String json = EntityUtils.toString(response.getEntity());
                    return objectMapper.readValue(json, Secret.class);
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
    public boolean deleteSecret(String path, DeleteOptions options) throws SecureVaultException {
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
    public List<String> listSecrets(String path, ListOptions options) throws SecureVaultException {
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
     * @return the token
     * @throws SecureVaultException if an error occurs
     */
    public String createToken(TokenOptions options) throws SecureVaultException {
        try {
            String uri = buildUri("/auth/token/create");
            HttpPost request = new HttpPost(uri);
            request.setEntity(createJsonEntity(options));
            
            try (CloseableHttpResponse response = executeRequest(request)) {
                if (response.getCode() == HttpStatus.SC_OK) {
                    String json = EntityUtils.toString(response.getEntity());
                    Map<String, String> result = objectMapper.readValue(json, 
                            new TypeReference<Map<String, String>>() {});
                    return result.get("token");
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
     */
    private String buildUri(String path) {
        return config.getAddress() + "/" + API_VERSION + path;
    }

    /**
     * Creates a JSON entity from an object.
     */
    private StringEntity createJsonEntity(Object obj) throws JsonProcessingException {
        return new StringEntity(objectMapper.writeValueAsString(obj), ContentType.APPLICATION_JSON);
    }

    /**
     * Executes an HTTP request with token authentication.
     */
    private CloseableHttpResponse executeRequest(HttpUriRequest request) throws IOException {
        request.setHeader("X-Vault-Token", token);
        return httpClient.execute(request);
    }

    /**
     * Handles error responses from the API.
     */
    private void handleErrorResponse(CloseableHttpResponse response) throws IOException {
        int statusCode = response.getCode();
        
        String errorMessage;
        try {
            String responseBody = EntityUtils.toString(response.getEntity());
            Map<String, String> errorMap = objectMapper.readValue(responseBody, 
                    new TypeReference<Map<String, String>>() {});
            errorMessage = errorMap.getOrDefault("error", "Unknown error");
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
         */
        public Builder address(String address) {
            this.address = address;
            return this;
        }
        
        /**
         * Sets the authentication token.
         */
        public Builder token(String token) {
            this.token = token;
            return this;
        }
        
        /**
         * Sets the maximum number of connections.
         */
        public Builder maxConnections(int maxConnections) {
            this.maxConnections = maxConnections;
            return this;
        }
        
        /**
         * Sets the maximum number of connections per route.
         */
        public Builder maxConnectionsPerRoute(int maxConnectionsPerRoute) {
            this.maxConnectionsPerRoute = maxConnectionsPerRoute;
            return this;
        }
        
        /**
         * Sets the request timeout in milliseconds.
         */
        public Builder requestTimeout(long requestTimeoutMillis) {
            this.requestTimeoutMillis = requestTimeoutMillis;
            return this;
        }
        
        /**
         * Sets the connect timeout in milliseconds.
         */
        public Builder connectTimeout(long connectTimeoutMillis) {
            this.connectTimeoutMillis = connectTimeoutMillis;
            return this;
        }
        
        /**
         * Builds the client.
         */
        public SecureVaultClient build() {
            // Validate required fields
            if (address == null || address.isEmpty()) {
                throw new IllegalArgumentException("Address is required");
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
}
