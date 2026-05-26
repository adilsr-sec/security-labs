# conftest.py — Disable broken third-party pytest plugins in this project
# The web3 package installed globally has an incompatible eth_typing version.
# This conftest prevents it from loading and crashing pytest.

collect_ignore_glob = []
