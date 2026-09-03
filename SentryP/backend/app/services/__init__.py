"""Service package for the Sentry backend.

The hash-chain utility is implemented in ``hash_chain.py``. Importing the
module here makes it available as ``backend.app.services.hash_chain`` which is
used by the ``events`` router.
"""

# Re-export the service modules so ``services.hash_chain`` / ``services.signatures``
# work without requiring an explicit import elsewhere.
from . import hash_chain  # noqa: F401
from . import signatures  # noqa: F401
