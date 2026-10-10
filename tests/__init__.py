"""NetSentinel test package.

Tests are run with::

    python -m unittest discover -s tests -v

They never open a raw socket, never require elevated privileges and never
contact an external network.
"""