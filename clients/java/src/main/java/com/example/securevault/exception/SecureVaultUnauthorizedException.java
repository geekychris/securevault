package com.example.securevault.exception;

/**
 * Exception thrown when authentication fails.
 */
public class SecureVaultUnauthorizedException extends SecureVaultException {
    /**
     * Creates a new exception with the given message.
     *
     * @param message the message
     */
    public SecureVaultUnauthorizedException(String message) {
        super(message);
    }

    /**
     * Creates a new exception with the given message and cause.
     *
     * @param message the message
     * @param cause   the cause
     */
    public SecureVaultUnauthorizedException(String message, Throwable cause) {
        super(message, cause);
    }
}

