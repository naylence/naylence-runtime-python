#!/bin/bash

# Docker Development Utility Script
# Helps manage Docker images for development and testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
IMAGE_PREFIX="naylence-runtime-integration"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  build       Build Docker image with current source code"
    echo "  rebuild     Force rebuild Docker image (no cache)"
    echo "  clean       Remove old Docker images"
    echo "  list        List all integration Docker images"
    echo "  test        Run integration tests with fresh Docker build"
    echo "  test-local  Run local RPC tests (no Docker)"
    echo "  test-logs   Run Docker tests with live container logs"
    echo "  logs        Show logs from the last test container"
    echo "  follow-logs Follow logs from running container in real-time"
    echo "  help        Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  PYTEST_DOCKER_REBUILD=true    Force rebuild images during tests"
    echo "  PYTEST_DOCKER_LOGS=true       Show live Docker container logs"
    echo ""
    echo "Examples:"
    echo "  $0 rebuild                     # Force rebuild with no cache"
    echo "  $0 test-logs                   # Run tests with live container logs"
    echo "  $0 follow-logs                 # Watch container logs in real-time"
    echo "  PYTEST_DOCKER_REBUILD=true $0 test  # Force rebuild during test"
    echo "  PYTEST_DOCKER_LOGS=true $0 test     # Show logs during test"
}

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

calculate_source_hash() {
    # Calculate hash of key source files
    local hash_input=""
    
    # Hash key files and directories
    for path in "src/naylence" "pyproject.toml" "poetry.lock" "tests/integration/docker/Dockerfile"; do
        if [[ -f "$PROJECT_ROOT/$path" ]]; then
            hash_input+=$(cat "$PROJECT_ROOT/$path")
        elif [[ -d "$PROJECT_ROOT/$path" ]]; then
            hash_input+=$(find "$PROJECT_ROOT/$path" -name "*.py" -type f -exec cat {} \; 2>/dev/null || true)
        fi
    done
    
    echo -n "$hash_input" | shasum -a 256 | cut -c1-12
}

build_image() {
    local force_rebuild=${1:-false}
    local source_hash=$(calculate_source_hash)
    local image_name="${IMAGE_PREFIX}:${source_hash}"
    
    if [[ "$force_rebuild" == "true" ]]; then
        local timestamp=$(date +%s)
        image_name="${IMAGE_PREFIX}:force-${timestamp}"
        log_info "Force rebuilding Docker image: $image_name"
    else
        # Check if image already exists
        if docker image inspect "$image_name" >/dev/null 2>&1; then
            log_success "Using existing Docker image: $image_name"
            return 0
        fi
        log_info "Building Docker image: $image_name (source hash: $source_hash)"
    fi
    
    # Build the image
    local dockerfile_path="$PROJECT_ROOT/tests/integration/docker/Dockerfile"
    
    if [[ "$force_rebuild" == "true" ]]; then
        docker build --no-cache -f "$dockerfile_path" -t "$image_name" "$PROJECT_ROOT"
    else
        docker build -f "$dockerfile_path" -t "$image_name" "$PROJECT_ROOT"
    fi
    
    log_success "Successfully built Docker image: $image_name"
}

clean_images() {
    log_info "Cleaning up old Docker images..."
    
    # Get all integration images sorted by creation time
    local images=$(docker images "${IMAGE_PREFIX}" --format "table {{.Repository}}:{{.Tag}}\t{{.CreatedAt}}" | tail -n +2 | sort -k2 -r)
    
    if [[ -z "$images" ]]; then
        log_info "No integration images found to clean"
        return 0
    fi
    
    local count=0
    local kept=0
    
    while IFS=$'\t' read -r image_tag created_at; do
        ((count++))
        if [[ $kept -lt 3 ]]; then
            log_info "Keeping recent image: $image_tag"
            ((kept++))
        else
            log_warning "Removing old image: $image_tag"
            docker rmi "$image_tag" 2>/dev/null || true
        fi
    done <<< "$images"
    
    log_success "Cleaned up $((count - kept)) old images, kept $kept recent images"
}

list_images() {
    log_info "Integration Docker images:"
    docker images "${IMAGE_PREFIX}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}" || {
        log_info "No integration images found"
    }
}

run_tests() {
    local test_type=${1:-docker}
    
    cd "$PROJECT_ROOT"
    
    case "$test_type" in
        "docker")
            log_info "Running Docker RPC integration tests..."
            python -m pytest tests/integration/sentinel/rpc/test_client_to_docker_sentinel.py -v -s
            ;;
        "docker-logs")
            log_info "Running Docker RPC integration tests with live logs..."
            PYTEST_DOCKER_LOGS=true python -m pytest tests/integration/sentinel/rpc/test_client_to_docker_sentinel.py -v -s
            ;;
        "local")
            log_info "Running local RPC tests..."
            python -m pytest tests/integration/sentinel/rpc/test_local_rpc.py -v -s
            ;;
        *)
            log_error "Unknown test type: $test_type"
            return 1
            ;;
    esac
}

show_logs() {
    log_info "Showing logs from last test container..."
    
    # Try to find the most recent test container
    local container_id=$(docker ps -a --filter "name=pytest-rpc-sentinel" --format "{{.ID}}" | head -n1)
    
    if [[ -n "$container_id" ]]; then
        docker logs "$container_id"
    else
        log_warning "No test container found"
        log_info "Available containers:"
        docker ps -a --filter "name=naylence" --format "table {{.Names}}\t{{.Status}}\t{{.CreatedAt}}"
    fi
}

follow_logs() {
    log_info "Following logs from running container..."
    
    # Try to find a running test container
    local container_id=$(docker ps --filter "name=pytest-rpc-sentinel" --format "{{.ID}}" | head -n1)
    
    if [[ -n "$container_id" ]]; then
        log_success "Following logs for container: $container_id"
        docker logs -f "$container_id"
    else
        log_warning "No running test container found"
        log_info "Available running containers:"
        docker ps --filter "name=naylence" --format "table {{.Names}}\t{{.Status}}\t{{.CreatedAt}}"
        
        # Check for any containers that might be starting
        local starting_container=$(docker ps -a --filter "name=pytest-rpc-sentinel" --filter "status=created" --format "{{.ID}}" | head -n1)
        if [[ -n "$starting_container" ]]; then
            log_info "Found starting container, following logs..."
            docker logs -f "$starting_container"
        fi
    fi
}

# Main command handling
case "${1:-help}" in
    "build")
        build_image false
        ;;
    "rebuild")
        build_image true
        ;;
    "clean")
        clean_images
        ;;
    "list")
        list_images
        ;;
    "test")
        run_tests docker
        ;;
    "test-local")
        run_tests local
        ;;
    "test-logs")
        run_tests docker-logs
        ;;
    "logs")
        show_logs
        ;;
    "follow-logs")
        follow_logs
        ;;
    "help"|*)
        print_usage
        ;;
esac
