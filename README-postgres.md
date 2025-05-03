# PostgreSQL Backend for SecureVault

This document describes how to set up and test the PostgreSQL backend for SecureVault.

## Overview

SecureVault includes a PostgreSQL backend option that provides several advantages over the file-based backend:

- **Scalability**: Better performance with many secrets
- **High availability**: Can leverage PostgreSQL's replication features
- **Transactional integrity**: Better data consistency guarantees
- **Backup and recovery**: Simplified and more robust backup options

## Prerequisites

To run the PostgreSQL backend tests, you'll need:

- Go 1.18 or newer
- Docker and Docker Compose (if using the provided Docker setup)
- PostgreSQL client (optional, for direct database interaction)

## Setting Up PostgreSQL for Testing

There are two ways to set up PostgreSQL for testing:

### Option 1: Using Docker (Recommended)

We provide a Docker Compose file that sets up PostgreSQL with all necessary configuration:

1. Start the PostgreSQL container:

```bash
docker-compose up -d postgres
```

2. Verify the container is running:

```bash
docker-compose ps
```

You should see the `securevault-postgres` container running.

3. Wait for PostgreSQL to initialize (usually takes a few seconds):

```bash
docker-compose logs -f postgres
```

Look for the message: "database system is ready to accept connections"

### Adding PostgreSQL to Your Project

If you're adding PostgreSQL support to an existing SecureVault deployment:

1. Add PostgreSQL connection details to your configuration file:

```yaml
storage:
  type: "postgres"
  postgres:
    host: "localhost"
    port: 5432
    user: "securevault"
    password: "securevault"
    dbname: "securevault"
    sslmode: "disable"  # Use "require" in production
```

2. Run the database initialization script:

```bash
psql -U securevault -d securevault -f scripts/init-postgres.sql
```

3. Start SecureVault with PostgreSQL support:

```bash
go run -tags postgres cmd/securevault/main.go
```

### Option 2: Using an Existing PostgreSQL Instance

If you prefer to use an existing PostgreSQL instance:

1. Create a database and user:

```sql
CREATE USER securevault WITH PASSWORD 'securevault';
CREATE DATABASE securevault OWNER securevault;
```

2. Apply the initialization script:

```bash
psql -U securevault -d securevault -f scripts/init-postgres.sql
```

3. Configure environment variables to point to your PostgreSQL instance (see Environment Variables section below).

## Running the PostgreSQL Tests

The PostgreSQL tests are disabled by default and must be explicitly enabled using build tags.

### Using Build Tags

The PostgreSQL tests are protected by the `postgres` build tag:

```bash
# Run only PostgreSQL tests
go test -tags postgres ./pkg/storage -v

# Run specific PostgreSQL test
go test -tags postgres ./pkg/storage -v -run TestPostgresBackendCRUD

# Run all tests including PostgreSQL tests
go test -tags postgres ./...
```

### Environment Variables

You can customize the PostgreSQL connection using these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| POSTGRES_HOST | PostgreSQL server host | localhost |
| POSTGRES_PORT | PostgreSQL server port | 5432 |
| POSTGRES_USER | PostgreSQL username | securevault |
| POSTGRES_PASSWORD | PostgreSQL password | securevault |
| POSTGRES_DB | PostgreSQL database name | securevault |
| POSTGRES_SSLMODE | SSL mode (disable, require, verify-ca, verify-full) | disable |

Example:

```bash
export POSTGRES_HOST=custom-postgres-host
export POSTGRES_PORT=5433
go test -tags postgres ./pkg/storage -v
```

## Building SecureVault with PostgreSQL Support

To build SecureVault with PostgreSQL support:

1. Install the PostgreSQL driver:

```bash
go get github.com/lib/pq
```

2. Build with the PostgreSQL tag:

```bash
go build -tags postgres -o securevault cmd/securevault/main.go
```

3. Configure SecureVault to use PostgreSQL in your config.yaml:

```yaml
storage:
  type: "postgres"
  postgres:
    host: "localhost"
    port: 5432
    user: "securevault"
    password: "securevault"
    dbname: "securevault"
    sslmode: "disable"  # Use "require" in production
```

## Example Test Workflow

Complete example workflow for testing:

```bash
# 1. Start PostgreSQL container
docker-compose up -d postgres

# 2. Wait for PostgreSQL to be ready
sleep 5

# 3. Run PostgreSQL tests
go test -tags postgres ./pkg/storage -v

# 4. Clean up
docker-compose down
```

## Troubleshooting

### Common Issues

1. **Connection Refused**

   Error: `dial tcp 127.0.0.1:5432: connect: connection refused`

   Solution: Ensure PostgreSQL is running with `docker-compose ps` or check your PostgreSQL service.

2. **Authentication Failed**

   Error: `password authentication failed for user "securevault"`

   Solution: Check the credentials match those in your environment variables.

3. **Test Database Not Clean**

   Some tests may fail if the database already contains data from previous test runs.

   Solution: Reset the database with:

   ```bash
   docker-compose down -v
   docker-compose up -d postgres
   ```

4. **Build Tag Missing**

   Error: `testing: warning: no tests to run`

   Solution: Ensure you're using the `-tags postgres` flag.

### Debugging PostgreSQL

To inspect the PostgreSQL database during or after tests:

```bash
# Connect to the PostgreSQL container
docker-compose exec postgres psql -U securevault -d securevault

# In PostgreSQL shell:
\dt                    # List tables
SELECT * FROM secrets; # View secrets table
```

## Performance Considerations

For optimal performance in production:

- Set appropriate connection pool sizes
- Consider using a connection pooler like PgBouncer
- Use SSD storage for the PostgreSQL data directory
- Configure PostgreSQL for your specific workload

## Migration from File Storage

To migrate data from file storage to PostgreSQL:

1. Export secrets from file storage:

```bash
# Using the SecureVault CLI
securevault export --output secrets.json
```

2. Set up PostgreSQL backend:

```bash
# Start PostgreSQL
docker-compose up -d postgres

# Initialize schema
psql -U securevault -d securevault -f scripts/init-postgres.sql
```

3. Import secrets into PostgreSQL storage:

```bash
# Using the SecureVault CLI with PostgreSQL backend
securevault import --file secrets.json --storage-type postgres
```

## Further Reading

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Docker PostgreSQL Image Documentation](https://hub.docker.com/_/postgres)
- [PostgreSQL Go Driver Documentation](https://github.com/lib/pq)
- [Go Database/SQL Tutorial](https://go.dev/doc/tutorial/database-access)
