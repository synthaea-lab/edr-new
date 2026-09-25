// Test setup - runs before all tests
import { config } from "dotenv";

// Load test environment variables
config({ path: ".env.test" });

// Set default test environment variables if not present
process.env.DATABASE_URL =
  process.env.DATABASE_URL ||
  "postgresql://synthaea:synthaea_test@localhost:5433/synthaea_test";

process.env.BETTER_AUTH_SECRET =
  process.env.BETTER_AUTH_SECRET || "test_secret_for_testing_only";

process.env.CRON_SECRET =
  process.env.CRON_SECRET || "test_cron_secret";

// Set NODE_ENV for tests
(process.env as { NODE_ENV: string }).NODE_ENV = "test";
