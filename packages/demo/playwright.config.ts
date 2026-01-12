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
        }
    ],
    webServer: {
        command: 'npm run dev',
        url: 'http://127.0.0.1:5173',
        reuseExistingServer: !process.env.CI,
        cwd: './'
    },
});
