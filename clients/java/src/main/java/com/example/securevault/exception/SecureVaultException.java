package com.example.securevault.exception;

/**
 * Exception thrown when an error occurs in the SecureVault client.
 */
public class SecureVaultException extends RuntimeException {
    /**
     * Creates a new exception with the given message.
     *
     * @param message the message
     */
    public SecureVaultException(String message) {
        super(message);
    }

    /**
     * Creates a new exception with the given message and cause.
     *
     * @param message the message
     * @param cause   the cause
     */
    public SecureVaultException(String message, Throwable cause) {
        super(message, cause);
    }
}

