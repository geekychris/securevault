#!/bin/bash
#
# SecureVault Setup Script
#
# This script helps set up a development environment for SecureVault.
# It checks prerequisites, builds the server and clients, and starts
# a development instance with default configuration.
#

set -e  # Exit immediately if a command exits with a non-zero status

# ANSI color codes for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Basic directories
BIN_DIR="./bin"
DATA_DIR="./data"
CONFIG_DIR="./configs"
DEV_CONFIG="$CONFIG_DIR/development.yaml"

# Print banner
echo -e "${BLUE}"
echo "  _____                          _    _            _ _   "
echo " / ____|                        | |  | |          | | |  "
echo "| (___   ___  ___ _   _ _ __ ___| |  | | __ _ _  _| | |_ "
echo " \___ \ / _ \/ __| | | | '__/ _ \ |  | |/ _' | || | | __|"
echo " ____) |  __/ (__| |_| | | |  __/ |__| | (_| |\__ \ | |_ "
echo "|_____/ \___|\___|\__,_|_|  \___|\____/ \__,_|  |_|_|\__|"
echo ""
echo -e "${NC}"
echo "Setup script for SecureVault development environment"
echo "======================================================"
echo ""

# Function to check if a command exists
check_command() {
  if ! command -v "$1" &> /dev/null; then
    echo -e "${RED}Error: $1 is not installed or not in your PATH${NC}"
    return 1
  fi
  return 0
}

# Check prerequisites
echo -e "${BLUE}Checking prerequisites...${NC}"

# Check for Go
if ! check_command go; then
  echo -e "${YELLOW}Go is required to build the server and Go client."
  echo -e "Please install Go 1.20 or later from https://golang.org/dl/${NC}"
  exit 1
fi

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
GO_VERSION_MAJOR=$(echo "$GO_VERSION" | cut -d. -f1)
GO_VERSION_MINOR=$(echo "$GO_VERSION" | cut -d. -f2)

if [[ "$GO_VERSION_MAJOR" -lt 1 || ("$GO_VERSION_MAJOR" -eq 1 && "$GO_VERSION_MINOR" -lt 20) ]]; then
  echo -e "${YELLOW}Warning: Go version 1.20 or later is recommended. Found $GO_VERSION${NC}"
  echo -e "You can continue, but some features may not work correctly."
  read -p "Continue anyway? (y/n) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
fi

# Check for Java (optional, only for Java client)
JAVA_AVAILABLE=false
if check_command java; then
  JAVA_VERSION=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}')
  JAVA_MAJOR_VERSION=$(echo "$JAVA_VERSION" | cut -d. -f1)
  
  if [[ "$JAVA_MAJOR_VERSION" -lt 17 ]]; then
    echo -e "${YELLOW}Warning: Java 17 or later is recommended for building the Java client."
    echo -e "Found Java $JAVA_VERSION${NC}"
    echo "Java client build will be skipped."
  else
    JAVA_AVAILABLE=true
  fi
else
  echo -e "${YELLOW}Java not found. Java client build will be skipped."
  echo -e "To build the Java client, install JDK 17 or later.${NC}"
fi

# Check for Maven if Java is available
MAVEN_AVAILABLE=false
if [[ "$JAVA_AVAILABLE" == true ]]; then
  if check_command mvn; then
    MAVEN_AVAILABLE=true
  else
    echo -e "${YELLOW}Maven not found. Java client build will be skipped."
    echo -e "To build the Java client, install Maven 3.6 or later.${NC}"
    JAVA_AVAILABLE=false
  fi
fi

echo -e "${GREEN}Prerequisites checked.${NC}"

# Create necessary directories
echo -e "${BLUE}Creating necessary directories...${NC}"
mkdir -p "$BIN_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$CONFIG_DIR"
echo -e "${GREEN}Directories created.${NC}"

# Create development configuration if it doesn't exist
if [[ ! -f "$DEV_CONFIG" ]]; then
  echo -e "${BLUE}Creating development configuration...${NC}"
  cat > "$DEV_CONFIG" << EOF
##
## SecureVault Development Configuration
##
server:
  address: "127.0.0.1"
  port: 8200
  tls:
    enabled: false

storage:
  type: "file"
  path: "./data"

auth:
  token_ttl: "24h"
  enable_unauthenticated_token_creation: true  # For development only

replication:
  mode: "standalone"

logging:
  level: "info"
  format: "text"
  output: "stdout"
  log_sensitive_data: false

performance:
  workers: 4
  max_concurrent_requests: 64
  cache_enabled: true
  cache_size_mb: 64
EOF
  echo -e "${GREEN}Development configuration created at $DEV_CONFIG${NC}"
else
  echo -e "${GREEN}Development configuration already exists at $DEV_CONFIG${NC}"
fi

# Build the server
echo -e "${BLUE}Building the server...${NC}"
go mod tidy
go build -o "$BIN_DIR/securevault" ./cmd/server
echo -e "${GREEN}Server built successfully.${NC}"

# Build the Go client and example
echo -e "${BLUE}Building Go client and example...${NC}"
mkdir -p "$BIN_DIR/examples"
go build -o "$BIN_DIR/examples/go-example" ./examples/go
echo -e "${GREEN}Go client and example built successfully.${NC}"

# Build the Java client if possible
if [[ "$JAVA_AVAILABLE" == true && "$MAVEN_AVAILABLE" == true ]]; then
  echo -e "${BLUE}Building Java client...${NC}"
  (cd clients/java && mvn clean package -DskipTests)
  echo -e "${GREEN}Java client built successfully.${NC}"
  
  echo -e "${BLUE}Building Java example...${NC}"
  (cd examples/java && mvn clean package -DskipTests)
  echo -e "${GREEN}Java example built successfully.${NC}"
fi

# Start the server in the background
echo -e "${BLUE}Starting SecureVault server in development mode...${NC}"
"$BIN_DIR/securevault" server --config "$DEV_CONFIG" > /tmp/securevault.log 2>&1 &
SERVER_PID=$!

# Wait for server to start
echo -e "${YELLOW}Waiting for server to start...${NC}"
MAX_RETRIES=30
count=0
while ! curl -s http://127.0.0.1:8200/v1/health > /dev/null; do
  sleep 1
  count=$((count+1))
  if [[ $count -gt $MAX_RETRIES ]]; then
    echo -e "${RED}Error: Server failed to start within 30 seconds.${NC}"
    echo "Check the logs at /tmp/securevault.log for details."
    kill $SERVER_PID 2>/dev/null || true
    exit 1
  fi
done

# Generate a root token
echo -e "${BLUE}Generating a root token...${NC}"
ROOT_TOKEN=$("$BIN_DIR/securevault" token create --policy root 2>/dev/null | grep -o "s\.[a-zA-Z0-9]\+")

if [[ -z "$ROOT_TOKEN" ]]; then
  echo -e "${YELLOW}Warning: Couldn't generate a token automatically."
  echo -e "You can create one manually with: bin/securevault token create --policy root${NC}"
  ROOT_TOKEN="<generate-manually>"
else
  echo -e "${GREEN}Root token generated successfully.${NC}"
fi

# Display summary and instructions
echo ""
echo -e "${GREEN}============ SecureVault Setup Complete ============${NC}"
echo ""
echo -e "SecureVault server is running at ${BLUE}http://127.0.0.1:8200${NC}"
echo -e "Root token: ${BLUE}$ROOT_TOKEN${NC}"
echo ""
echo "Next steps:"
echo ""
echo -e "1. Try creating a secret:"
echo -e "   ${YELLOW}curl -H \"X-Vault-Token: $ROOT_TOKEN\" -X POST \\"
echo -e "        -d '{\"data\": {\"username\": \"test\", \"password\": \"secret\"}}' \\"
echo -e "        http://127.0.0.1:8200/v1/secret/my-first-secret${NC}"
echo ""
echo -e "2. Read the secret:"
echo -e "   ${YELLOW}curl -H \"X-Vault-Token: $ROOT_TOKEN\" \\"
echo -e "        http://127.0.0.1:8200/v1/secret/my-first-secret${NC}"
echo ""
echo -e "3. Run the Go example:"
echo -e "   ${YELLOW}$BIN_DIR/examples/go-example http://127.0.0.1:8200 $ROOT_TOKEN${NC}"
echo ""
if [[ "$JAVA_AVAILABLE" == true && "$MAVEN_AVAILABLE" == true ]]; then
  echo -e "4. Run the Java example:"
  echo -e "   ${YELLOW}java -jar examples/java/target/securevault-example-1.0.0.jar http://127.0.0.1:8200 $ROOT_TOKEN${NC}"
  echo ""
fi
echo -e "To stop the server, run: ${YELLOW}kill $SERVER_PID${NC}"
echo ""
echo -e "For more information, see the README.md file."
echo -e "${GREEN}=====================================================${NC}"

# Save the PID for later use
echo "$SERVER_PID" > /tmp/securevault.pid

