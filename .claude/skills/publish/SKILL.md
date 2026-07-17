---
name: publish
description: Validate the Jekyll site with Playwright and publish if it passes. Use when the user wants to build, preview, and push site changes.
allowed-tools: Bash, Read, Write
---

# publish

Validate the Jekyll site with Playwright and publish if it passes.

## Steps

### 1. Build

Run a clean Jekyll build and fail fast on errors:

```bash
bundle exec jekyll build 2>&1
```

If the build exits non-zero or prints `Error:` / `Liquid Exception`, stop and report the error. Do not proceed.

### 1b. Static rendering-integrity checks

Grep the built `_site` for known formatting regressions before the browser pass. These
are deterministic and cheap; any hit stops the publish.

```bash
# TOC id-leak: post.html builds the Table of Contents from heading HTML. If the title
# extraction regresses, entries render as `some-id">Title` instead of `Title`. The tell
# is a second `">` inside a TOC <li> link. Must be zero.
leak=$(grep -rho '<li><a href="#[^<]*</a></li>' _site/ctf/ | grep -cE '">[^<]*">')
echo "TOC id-leak entries: $leak"   # must be 0

# Unrendered pipe tables: a kramdown table that didn't parse leaves a literal `|---|`
# separator row in the HTML body. Must be zero.
badtbl=$(grep -rlE '\|[[:space:]]*-{3,}' _site/ctf/ | wc -l)
echo "pages with unrendered tables: $badtbl"   # must be 0

# Broken local images: every /assets img referenced by a built page must exist on disk.
```

If `leak` or `badtbl` is non-zero, stop and fix the template/source — do not publish.
The TOC generator lives in `_layouts/post.html`; titles come from heading inner-HTML with
the `id">` opening prefix removed via `remove_first` (not a `">` split, which breaks on
headings that contain inline `<code>`/links).

### 2. Serve

Start the dev server in the background:

```bash
bundle exec jekyll serve --no-watch --skip-initial-build &
sleep 3
```

### 3. Validate with Playwright

Run a Playwright script to check the site. Write it to a temp file and execute it:

```bash
cat > /tmp/validate-site.js << 'EOF'
const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const base = 'http://localhost:4000';
  const errors = [];

  const checks = [
    { url: '/', label: 'Home' },
    { url: '/articles/projects/', label: 'Projects nav' },
  ];

  // Also check any page passed as CLI args
  const extra = process.argv.slice(2);
  for (const u of extra) checks.push({ url: u, label: u });

  for (const { url, label } of checks) {
    await page.goto(base + url, { waitUntil: 'networkidle' });

    // Screenshot for visual review
    const slug = label.replace(/[^a-z0-9]/gi, '-').toLowerCase();
    await page.screenshot({ path: `/tmp/preview-${slug}.png`, fullPage: false });

    // Check no Jekyll error page
    const title = await page.title();
    if (title.includes('404') || title.includes('Error')) {
      errors.push(`${label}: got error page (title: "${title}")`);
    }

    // Check nav contains Projects
    const hasProjects = await page.locator('text=Projects').count();
    if (hasProjects === 0) {
      errors.push(`${label}: "Projects" not found in nav`);
    }
  }

  await browser.close();

  if (errors.length > 0) {
    console.error('VALIDATION FAILED:\n' + errors.join('\n'));
    process.exit(1);
  } else {
    console.log('All checks passed.');
    console.log('Screenshots saved to /tmp/preview-*.png');
  }
})();
EOF
node /tmp/validate-site.js $ARGUMENTS
```

Read and display each screenshot at `/tmp/preview-*.png` so the user can visually confirm the nav and layout look correct.

### 4. Stop the server

```bash
kill $(lsof -t -i:4000) 2>/dev/null || true
```

### 5. Publish

Only proceed after the user explicitly confirms the screenshots look correct.

```bash
git add -A
git status
```

Show the user the staged files, then ask for confirmation before committing. Use conventional commit format:

```
git commit -m "$(cat <<'EOF'
feat(articles): publish <article title>

<one-sentence summary of what was added/changed>

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
git push
```
