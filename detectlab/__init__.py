"""Detection-as-code toolkit for the CyberPulse SOC Lab.

Author: Chandu Komme

The package evaluates Sigma rules offline against synthetic events, lints the
rule catalog, and generates MITRE ATT&CK coverage artifacts. It lets every
detection be tested in CI without starting the Docker stack.
"""

__author__ = "Chandu Komme"
__version__ = "3.0.0"
