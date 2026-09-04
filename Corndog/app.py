"""
vuln_test_app.py

INTENTIONALLY VULNERABLE test fixture for Checkmarx One SAST scanner validation.
Do NOT deploy this. Do NOT expose it to a network. For scan-testing purposes only.

Contains:
  1. Command Injection - ping_host()

Takes unsanitized input and passes it straight into a sink (os.system) so
SAST should flag it as a tainted data flow.
"""

import os


def ping_host(host):
    """
    VULNERABLE: OS Command Injection (CWE-78)
    User-controlled 'host' is passed straight to os.system() with no
    validation or use of a safe subprocess call (e.g. subprocess.run with a
    list of args and shell=False).
    """
    command = "ping -c 1 " + host
    os.system(command)


def main():
    print("=== Command Injection test ===")
    host = input("Enter a host to ping: ")
    ping_host(host)


if __name__ == "__main__":
    main()
