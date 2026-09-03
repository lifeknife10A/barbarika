import json
from backend.app.main import app

routes = []
for r in app.routes:
    routes.append({"path": getattr(r, "path", None), "methods": sorted(list(getattr(r, "methods", [])))})
print(json.dumps(routes, indent=2))
