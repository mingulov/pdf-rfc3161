import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
    testDir: './test/e2e',
    fullyParallel: true,
    timeout: 60000,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    workers: process.env.CI ? 1 : undefined,
    reporter: [
        ['list'],
        ['json'],
        ['html', { open: 'never' }]
    ],
    use: {
        baseURL: 'http://127.0.0.1:5173',
        trace: 'on-first-retry',
    },
    projects: [
        {
            name: 'chromium',
            use: { ...devices['Desktop Chrome'] },
        },
        {
            name: 'firefox',
            use: { ...devices['Desktop Firefox'] },
        },
        {
            name: 'webkit',
            use: { ...devices['Desktop Safari'] },
        }
    ],
    webServer: {
        command: 'pnpm run dev',
        url: 'http://127.0.0.1:5173',
        // Loaded CI runners can exceed the 60s default after the signing
        // gate; pipe the server output so the next slow-start failure
        // shows what vite was doing instead of bare silence.
        timeout: 120000,
        stdout: 'pipe',
        stderr: 'pipe',
        reuseExistingServer: !process.env.CI,
        cwd: './'
    },
});
