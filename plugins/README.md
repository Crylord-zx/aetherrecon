# AetherRecon Plugins

Place custom Python plugin files here. Each plugin must have a `register()` function.

See `example_plugin.py` for a working template.

## Plugin Structure

```python
from aetherrecon.modules.base import BaseModule

class MyPlugin(BaseModule):
    name = "my_plugin"
    category = "vuln"  # passive, active, or vuln
    description = "What this plugin does"

    async def run(self, target: str) -> list[dict]:
        # Your logic here
        return results

def register():
    return {
        "name": "my_plugin",
        "description": "Plugin description",
        "module_class": MyPlugin,
        "version": "1.0.0",
    }
```
