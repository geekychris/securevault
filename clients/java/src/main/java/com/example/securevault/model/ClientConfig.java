package com.example.securevault.model;

/**
 * Configuration for the SecureVault client.
 * Contains settings for server connection, authentication, and HTTP client behavior.
 */
public class ClientConfig {
    /**
     * The address of the SecureVault server (required).
     * Format: "http://hostname:port" or "https://hostname:port"
     */
    private String address;
    
    /**
     * The authentication token for the SecureVault server (optional).
     * If not provided, authentication methods must be used to obtain a token.
     */
    private String token;
    
    /**
     * The maximum number of connections in the connection pool.
     * Default: 20
     */
    private int maxConnections = 20;
    
    /**
     * The maximum number of connections per route.
     * Default: 10
     */
    private int maxConnectionsPerRoute = 10;
    
    /**
     * The request timeout in milliseconds.
     * Default: 10,000 (10 seconds)
     */
    private long requestTimeoutMillis = 10_000;
    
    /**
     * The connection timeout in milliseconds.
     * Default: 5,000 (5 seconds)
     */
    private long connectTimeoutMillis = 5_000;
    
    /**
     * Gets the server address.
     *
     * @return the server address
     */
    public String getAddress() {
        return address;
    }
    
    /**
     * Sets the server address.
     *
     * @param address the server address (required)
     * @throws IllegalArgumentException if address is null or empty
     */
    public void setAddress(String address) {
        if (address == null || address.trim().isEmpty()) {
            throw new IllegalArgumentException("Server address cannot be null or empty");
        }
        this.address = address;
    }
    
    /**
     * Gets the authentication token.
     *
     * @return the authentication token, or null if not set
     */
    public String getToken() {
        return token;
    }
    
    /**
     * Sets the authentication token.
     *
     * @param token the authentication token (optional)
     */
    public void setToken(String token) {
        this.token = token;
    }
    
    /**
     * Gets the maximum number of connections.
     *
     * @return the maximum number of connections
     */
    public int getMaxConnections() {
        return maxConnections;
    }
    
    /**
     * Sets the maximum number of connections.
     *
     * @param maxConnections the maximum number of connections
     * @throws IllegalArgumentException if maxConnections is less than 1
     */
    public void setMaxConnections(int maxConnections) {
        if (maxConnections < 1) {
            throw new IllegalArgumentException("Maximum connections must be at least 1");
        }
        this.maxConnections = maxConnections;
    }
    
    /**
     * Gets the maximum number of connections per route.
     *
     * @return the maximum number of connections per route
     */
    public int getMaxConnectionsPerRoute() {
        return maxConnectionsPerRoute;
    }
    
    /**
     * Sets the maximum number of connections per route.
     *
     * @param maxConnectionsPerRoute the maximum number of connections per route
     * @throws IllegalArgumentException if maxConnectionsPerRoute is less than 1
     */
    public void setMaxConnectionsPerRoute(int maxConnectionsPerRoute) {
        if (maxConnectionsPerRoute < 1) {
            throw new IllegalArgumentException("Maximum connections per route must be at least 1");
        }
        this.maxConnectionsPerRoute = maxConnectionsPerRoute;
    }
    
    /**
     * Gets the request timeout in milliseconds.
     *
     * @return the request timeout in milliseconds
     */
    public long getRequestTimeoutMillis() {
        return requestTimeoutMillis;
    }
    
    /**
     * Sets the request timeout in milliseconds.
     *
     * @param requestTimeoutMillis the request timeout in milliseconds
     * @throws IllegalArgumentException if requestTimeoutMillis is less than 0
     */
    public void setRequestTimeoutMillis(long requestTimeoutMillis) {
        if (requestTimeoutMillis < 0) {
            throw new IllegalArgumentException("Request timeout cannot be negative");
        }
        this.requestTimeoutMillis = requestTimeoutMillis;
    }
    
    /**
     * Gets the connect timeout in milliseconds.
     *
     * @return the connect timeout in milliseconds
     */
    public long getConnectTimeoutMillis() {
        return connectTimeoutMillis;
    }
    
    /**
     * Sets the connect timeout in milliseconds.
     *
     * @param connectTimeoutMillis the connect timeout in milliseconds
     * @throws IllegalArgumentException if connectTimeoutMillis is less than 0
     */
    public void setConnectTimeoutMillis(long connectTimeoutMillis) {
        if (connectTimeoutMillis < 0) {
            throw new IllegalArgumentException("Connect timeout cannot be negative");
        }
        this.connectTimeoutMillis = connectTimeoutMillis;
    }
}

