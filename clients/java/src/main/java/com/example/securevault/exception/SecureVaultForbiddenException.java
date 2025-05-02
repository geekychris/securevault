package com.example.securevault.exception;

/**
 * Exception thrown when a request is forbidden.
 */
public class SecureVaultForbiddenException extends SecureVaultException {
    /**
     * Creates a new exception with the given message.
     *
     * @param message the message
     */
    public SecureVaultForbiddenException(String message) {
        super(message);
    }

    /**
     * Creates a new exception with the given message and cause.
     *
     * @param message the message
     * @param cause   the cause
     */
    public SecureVaultForbiddenException(String message, Throwable cause) {
        super(message, cause);
    }
}

