# Vaultrix Directory Structure

This document provides an overview of the Vaultrix project's directory structure and explains the purpose of key components.

## Project Layout

```
securevault/
├── bin/                       # Compiled binaries
├── cmd/                       # Command-line applications
│   └── server/                # Main server application entry point
│       └── main.go            # Main server entry point
├── pkg/                       # Core packages
│   ├── server/                # Server implementation
│   │   ├── server.go          # Core server implementation
│   │   └── server_test.go     # Server tests
│   ├── policy/                # Policy management
│   │   └── policy.go          # Policy definition and enforcement
│   ├── storage/               # Storage backends
│   │   └── storage.go         # Storage interface and implementations
│   └── replication/           # Replication functionality
│       └── replication.go     # Replication implementation
├── clients/                   # Client libraries
│   ├── go/                    # Go client
│   │   ├── client.go          # Go client implementation
│   │   └── client_test.go     # Go client tests
│   └── java/                  # Java client
│       ├── pom.xml            # Maven project configuration
│       └── src/               # Java source files
│           └── main/java/com/example/securevault/
│               ├── SecureVaultClient.java               # Main client class
│               ├── config/                              # Client configuration
│               ├── exception/                           # Exception classes
│               └── model/                               # Data model classes
├── examples/                  # Example applications
│   ├── go/                    # Go examples
│   │   └── main.go            # Go client example
│   └── java/                  # Java examples
│       └── src/main/java/com/example/securevault/examples/
│           └── SecureVaultExample.java                  # Java client example
├── docs/                      # Documentation
├── config.yaml                # Sample configuration file
├── go.mod                     # Go module definition
├── go.sum                     # Go dependency checksums
├── README.md                  # Project overview and documentation
├── DIRECTORY_STRUCTURE.md     # This file
└── LICENSE                    # License information
```

## Core Components

### Command Line Applications (`cmd/`)

This directory contains the main executable applications:

- `cmd/server/main.go`: The main entry point for the server application. It parses command-line flags, loads configuration, initializes the server, and handles signals for graceful shutdown.

### Core Packages (`pkg/`)

The `pkg` directory contains the core functionality of Vaultrix:

#### Server Package (`pkg/server/`)

- `server.go`: Implements the `Server` type, which coordinates all components of the Vaultrix system. It handles HTTP endpoints, authentication, and routing requests to the appropriate handlers.
- `server_test.go`: Contains tests for the server functionality, including API endpoints, authentication, and access control.

#### Policy Package (`pkg/policy/`)

- `policy.go`: Defines the policy data structures and implements the policy enforcement logic. Policies control which paths clients can access and what operations they can perform.

#### Storage Package (`pkg/storage/`)

- `storage.go`: Defines the storage interface and implements various storage backends. The storage layer is responsible for persisting secrets and metadata.

#### Replication Package (`pkg/replication/`)

- `replication.go`: Implements replication functionality between leader and follower nodes, enabling high availability and load distribution.

### Client Libraries (`clients/`)

The `clients` directory contains client libraries for different programming languages:

#### Go Client (`clients/go/`)

- `client.go`: Implements the Go client library, which provides a programmatic interface to Vaultrix.
- `client_test.go`: Contains tests for the Go client implementation.

#### Java Client (`clients/java/`)

- `src/main/java/com/example/securevault/SecureVaultClient.java`: Main Java client class that provides methods for interacting with the Vaultrix server.
- `src/main/java/com/example/securevault/config/`: Contains configuration classes for the Java client.
- `src/main/java/com/example/securevault/exception/`: Contains custom exceptions for the Java client.
- `src/main/java/com/example/securevault/model/`: Contains data model classes for the Java client.

### Examples (`examples/`)

The `examples` directory contains example applications demonstrating the usage of Vaultrix clients:

- `examples/go/main.go`: Example Go application that demonstrates common operations with the Go client.
- `examples/java/src/main/java/com/example/securevault/examples/SecureVaultExample.java`: Example Java application that demonstrates common operations with the Java client.

## Configuration

- `config.yaml`: Sample configuration file showing all available options for the server.

## Key File Relationships

1. **Server Initialization Flow**:
   - `cmd/server/main.go` → Loads config → Initializes `pkg/server/server.go` → Server uses `pkg/policy/policy.go` and `pkg/storage/storage.go`

2. **Client Operation Flow**:
   - Client code → Makes API request → Server handles in appropriate handler → Policy check → Storage operation → Response

3. **Replication Flow**:
   - Write operations to leader → Leader processes and stores → Leader replicates to followers → Followers update their storage

## Special Files

- `go.mod` and `go.sum`: Define Go module dependencies
- `clients/java/pom.xml`: Defines Java client dependencies and build configuration
- `README.md`: Main documentation file with usage instructions
- `LICENSE`: License information for the project

## Directory Naming Conventions

- Go packages follow the standard Go naming conventions (lowercase, single word)
- Java packages follow Java conventions (com.example.component)
- Test files are named with the `_test.go` suffix in Go
- Implementation files are typically named after their primary component (e.g., `server.go` for the server implementation)

## Adding New Components

When adding new components to Vaultrix:

1. Server features should be added to the appropriate package in `pkg/`
2. Client features should be added to the respective client library in `clients/`
3. Command-line functionality should be added to `cmd/`
4. Examples showing the new features should be added to `examples/`
5. Documentation should be updated in `README.md` and other documentation files

