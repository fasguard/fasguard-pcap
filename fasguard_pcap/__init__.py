# __init__.py must exist for Python to recognize this directory as a
# package, but Python should load __init__.so instead of this
# __init__.py.
raise ImportError("__init__.py loaded; should have loaded __init__.so")
