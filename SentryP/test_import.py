import backend.app.routes.events as ev
print('Imported events module')
print('Number of routes:', len(ev.router.routes))
for route in ev.router.routes:
    print('Route path:', route.path, 'methods:', route.methods)
