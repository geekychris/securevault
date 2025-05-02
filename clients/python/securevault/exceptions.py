"""
Exceptions for the SecureVault Python client.
"""

class SecureVaultError(Exception):
    """Base exception for all SecureVault related errors."""
    
    def __init__(self, message: str, status_code: int = None):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class SecureVaultConnectionError(SecureVaultError):
    """Exception raised for connection errors."""
    
    def __init__(self, message: str = "Failed to connect to SecureVault server"):
        super().__init__(message)


class SecureVaultAuthenticationError(SecureVaultError):
    """Exception raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, 401)


class SecureVaultForbiddenError(SecureVaultError):
    """Exception raised when permission is denied."""
    
    def __init__(self, message: str = "Permission denied"):
        super().__init__(message, 403)


class SecureVaultNotFoundError(SecureVaultError):
    """Exception raised when a resource is not found."""
    
    def __init__(self, message: str = "Resource not found"):
        super().__init__(message, 404)


class SecureVaultBadRequestError(SecureVaultError):
    """Exception raised when the request is invalid."""
    
    def __init__(self, message: str = "Bad request"):
        super().__init__(message, 400)


class SecureVaultServerError(SecureVaultError):
    """Exception raised when the server encounters an error."""
    
    def __init__(self, message: str = "Server error"):
        super().__init__(message, 500)

