"""Service package for the Sentry backend.

The hash-chain utility is implemented in ``hash_chain.py``. Importing the
module here makes it available as ``backend.app.services.hash_chain`` which is
used by the ``events`` router.
"""

# Re-export the hash_chain module so that ``services.hash_chain`` works without
# requiring an explicit import elsewhere.
from . import hash_chain  # noqa: F401
