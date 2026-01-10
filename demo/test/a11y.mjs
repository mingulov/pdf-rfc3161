import { chromium } from "playwright";
import http from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function startServer() {
    const demoPath = path.join(__dirname, "..", "dist");
    const indexPath = path.join(demoPath, "index.html");

    if (!fs.existsSync(indexPath)) {
        throw new Error(`index.html not found at ${indexPath}`);
    }

    return new Promise((resolve) => {
        const server = http.createServer((req, res) => {
            let urlPath = req.url.split("?")[0];
            urlPath = path.normalize(urlPath).replace(/^(\.\.[\/\\])+/, "");
            let filePath = path.join(
                demoPath,
                urlPath === "" || urlPath === "/" ? "index.html" : urlPath
            );

            if (!filePath.startsWith(demoPath)) {
                res.writeHead(403);
                res.end("Forbidden");
                return;
            }

            const ext = path.extname(filePath);
            const mimeTypes = {
                ".html": "text/html",
                ".js": "application/javascript",
                ".css": "text/css",
                ".json": "application/json",
                ".png": "image/png",
                ".svg": "image/svg+xml",
            };
            const contentType = mimeTypes[ext] || "application/octet-stream";

            fs.readFile(filePath, (err, data) => {
                if (err) {
                    res.writeHead(404);
                    res.end("Not found");
                } else {
                    res.writeHead(200, { "Content-Type": contentType });
                    res.end(data);
                }
            });
        });
        server.listen(0, "127.0.0.1", () => {
            const port = server.address().port;
            resolve({ server, port });
        });
    });
}

async function testAccessibility() {
    const { server, port } = await startServer();
    const browser = await chromium.launch();
    const page = await browser.newPage();

    const errors = [];
    const warnings = [];

    // Collect console errors
    page.on("console", (msg) => {
        if (msg.type() === "error") {
            errors.push(`Console Error: ${msg.text()}`);
        }
    });

    // Collect page errors
    page.on("pageerror", (error) => {
        errors.push(`Page Error: ${error.message}`);
    });

    try {
        await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "networkidle" });

        // Wait for React to render
        await page.waitForSelector(".app", { timeout: 10000 });

        console.log("=== Page loaded successfully ===\n");

        // Check for images without alt
        const imagesWithoutAlt = await page.$$eval("img:not([alt])", (imgs) =>
            imgs.map((img) => img.getAttribute("src") || "unknown")
        );
        if (imagesWithoutAlt.length > 0) {
            warnings.push(`Images without alt: ${imagesWithoutAlt.join(", ")}`);
        }

        // Check for links without accessible text
        const linksWithoutText = await page.$$eval("a", (links) =>
            links
                .filter((a) => !a.textContent?.trim() && !a.getAttribute("aria-label"))
                .map((a) => a.getAttribute("href") || "no-href")
        );
        if (linksWithoutText.length > 0) {
            warnings.push(`Links without accessible text: ${linksWithoutText.join(", ")}`);
        }

        // Check for buttons without accessible text
        const buttonsWithoutText = await page.$$eval("button", (buttons) =>
            buttons
                .filter((btn) => !btn.textContent?.trim() && !btn.getAttribute("aria-label"))
                .map((btn) => btn.innerHTML.slice(0, 50))
        );
        if (buttonsWithoutText.length > 0) {
            warnings.push(`Buttons without accessible text: ${buttonsWithoutText.join(", ")}`);
        }

        // Check for form inputs without labels
        const inputsWithoutLabels = await page.$$eval(
            'input:not([type="hidden"]):not([aria-hidden="true"])',
            (inputs) => {
                const results = [];
                for (const input of inputs) {
                    const id = input.id;
                    const hasAriaLabel = input.getAttribute("aria-label");
                    const hasAriaLabelledby = input.getAttribute("aria-labelledby");
                    if (!hasAriaLabel && !hasAriaLabelledby && !id) {
                        results.push(`<input type="${input.type}" id="${id || "no-id"}">`);
                    }
                }
                return results;
            }
        );
        if (inputsWithoutLabels.length > 0) {
            warnings.push(`Inputs without labels: ${inputsWithoutLabels.join(", ")}`);
        }

        // Check for missing h1
        const h1Count = await page.locator("h1").count();
        if (h1Count === 0) {
            warnings.push("No <h1> element found on page");
        } else if (h1Count > 1) {
            warnings.push(`Multiple <h1> elements found (${h1Count})`);
        }

        // Check heading hierarchy
        const headings = await page.$$eval("h1, h2, h3, h4, h5, h6", (els) =>
            els.map((el) => ({
                level: el.tagName,
                text: el.textContent?.slice(0, 30).trim(),
            }))
        );
        let lastLevel = 0;
        for (const h of headings) {
            const level = parseInt(h.level.slice(1));
            if (level > lastLevel + 1 && lastLevel > 0) {
                warnings.push(`Heading level jump: ${h.level} "${h.text}" follows h${lastLevel}`);
            }
            lastLevel = level;
        }

        // Check for role conflicts
        const badRoles = await page.$$eval('*[role=""]', (els) =>
            els.map((el) => el.tagName.toLowerCase())
        );
        if (badRoles.length > 0) {
            warnings.push(`Elements with empty role: ${[...new Set(badRoles)].join(", ")}`);
        }

        // Check tabpanel has aria-labelledby
        const tabpanels = await page.$$('[role="tabpanel"]');
        for (const tp of tabpanels) {
            const labelledby = await tp.getAttribute("aria-labelledby");
            if (!labelledby) {
                warnings.push('<div role="tabpanel"> without aria-labelledby');
            }
        }

        // Check tabs have aria-controls
        const tabs = await page.$$('[role="tab"]');
        for (const tab of tabs) {
            const controls = await tab.getAttribute("aria-controls");
            if (!controls) {
                warnings.push('<button role="tab"> without aria-controls');
            }
        }

        // Check fieldsets have legends
        const fieldsets = await page.$$("fieldset");
        for (const fs of fieldsets) {
            const legend = await fs.$("legend");
            if (!legend) {
                warnings.push("<fieldset> without <legend>");
            }
        }

        // Check for empty headings
        const emptyHeadings = await page.$$eval("h1, h2, h3, h4, h5, h6", (els) =>
            els.filter((el) => !el.textContent?.trim()).map((el) => el.tagName.toLowerCase())
        );
        if (emptyHeadings.length > 0) {
            warnings.push(`Empty headings: ${[...new Set(emptyHeadings)].join(", ")}`);
        }

        // Check that download buttons have aria-label
        const downloadButtons = await page.$$eval("button", (buttons) =>
            buttons
                .filter((btn) => btn.innerHTML.includes("Download"))
                .map((btn) => btn.getAttribute("aria-label") || "no-aria-label")
        );
        const missingAriaLabels = downloadButtons.filter((a) => a === "no-aria-label");
        if (missingAriaLabels.length > 0) {
            warnings.push(`${missingAriaLabels.length} download button(s) missing aria-label`);
        }

        // Console errors from JavaScript
        if (errors.length > 0) {
            console.log("=== ERRORS ===");
            errors.forEach((e) => console.log(`  [X] ${e}`));
        }

        // Warnings
        if (warnings.length > 0) {
            console.log("\n=== WARNINGS ===");
            warnings.forEach((w) => console.log(`  [!] ${w}`));
        }

        if (errors.length === 0 && warnings.length === 0) {
            console.log("[OK] No accessibility issues found!");
        }

        console.log("\n=== SUMMARY ===");
        console.log(`Errors: ${errors.length}`);
        console.log(`Warnings: ${warnings.length}`);
    } catch (error) {
        console.error("Test failed:", error);
    } finally {
        await browser.close();
        server.close();
    }
}

testAccessibility();
