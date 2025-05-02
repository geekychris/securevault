package com.example.securevault.exception;

/**
 * Exception thrown when a resource is not found.
 */
public class SecureVaultNotFoundException extends SecureVaultException {
    /**
     * Creates a new exception with the given message.
     *
     * @param message the message
     */
    public SecureVaultNotFoundException(String message) {
        super(message);
    }

    /**
     * Creates a new exception with the given message and cause.
     *
     * @param message the message
     * @param cause   the cause
     */
    public SecureVaultNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}

