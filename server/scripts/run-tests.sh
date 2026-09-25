#!/bin/bash
# Run full test suite with test database

set -e

echo "Starting test database..."
docker-compose -f docker-compose.test.yml up -d

echo "Waiting for database to be ready..."
sleep 5

echo "Running Prisma migrations..."
DATABASE_URL="postgresql://synthaea:synthaea_test@localhost:5433/synthaea_test" \
  npx prisma migrate deploy

echo ""
echo "Running unit tests..."
npm test tests/unit

echo ""
echo "Running integration tests..."
npm test tests/integration

echo ""
echo "Test summary:"
echo "  ✓ Unit tests passed"
echo "  ✓ Integration tests passed"
echo ""
echo "To run E2E tests, start the dev stack and run:"
echo "  npm run test:e2e"
echo ""

# Cleanup
echo "Stopping test database..."
docker-compose -f docker-compose.test.yml down
