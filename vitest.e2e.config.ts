import { defineConfig } from 'vitest/config'

// E2E config: drives real HTTP against the spawned target-app.
// Isolated from the mock-based unit/integration suite (which uses undici MockAgent).
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['__tests__/e2e/**/*.e2e.test.ts'],
    testTimeout: 60000,
    hookTimeout: 30000,
    // No coverage thresholds here — E2E measures detection capability, not line coverage.
  },
})
