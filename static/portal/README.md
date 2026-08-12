# Portal artwork

Replace these local files with the official optimized event artwork:

- `logo.svg`
- `bg-mobile.jpg` (target composition: 1080 × 1920, ideally under 1 MB)
- `bg-tablet-portrait.jpg` (1536 × 2048, ideally under 1.5 MB)
- `bg-tablet-landscape.jpg` (2048 × 1536, ideally under 1.5 MB)
- `bg-desktop.jpg` (2560 × 1440, ideally under 2 MB)

The JPG files are intentionally absent until official artwork is supplied. CSS gradients provide the temporary background, and each expected image URL is already wired into `portal.css`.

Keep logos and text out of the JPG backgrounds. `logo.svg` is loaded as a separate responsive image. If it cannot load, the templates show a plain `EVENT` text fallback.

To re-theme the portal, replace the artwork above and edit the `--portal-*` custom properties at the beginning of `portal.css`. No Python, UniFi, database, or form changes are required.
