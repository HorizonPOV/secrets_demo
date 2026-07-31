"""
Checkmarx Secrets Detection - SSH Key Demo
Purpose: Demonstrate how Secrets Detection separates a REAL high-entropy
private key from low-entropy placeholders using entropy + contextual analysis.

Notes for the demo:
  - The key below is a THROWAWAY key generated only for this demo.
    It is not used by any system and grants access to nothing.
  - Expectation in Checkmarx One Secrets Detection:
      * REAL_DEPLOY_KEY        -> flagged (high Shannon entropy, valid PEM structure)
      * PLACEHOLDER_KEY        -> NOT flagged (low entropy, obvious placeholder)
      * EXAMPLE_KEY_IN_COMMENT -> de-prioritized / filtered (example/test context)
"""

import io
import os
import paramiko


# ---------------------------------------------------------------------------
# CASE 1: REAL hardcoded private key  -> EXPECTED: DETECTED
# High entropy, well-formed PEM. This is the true positive.
# ---------------------------------------------------------------------------
REAL_DEPLOY_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDINvXAY6xdCuc
JbIbRvHeNdJTk29EiTFDlk//+AE91R0vbMXR+eBAPCbvJZ5k0TmxWnmPribqdB9e
d7oLSTk07NIE1DBA/CO9u9VLACOzQEJz6K+yu16gUWC0NoaDg7GvMIBDbZU8jT5F
NX6kbL1gEg8PUeKh9YGVx6PRyvhOPI2VnPhnHAvAtEpiUbY7DYrcT6GmUOKoI5x0
Y50hra9hPeivzGwi0WV0l8SMH5E5/gdralzzben91heK/9vFTOgOcN/f1yjVr7iP
lVBErxyl5wMbLuvOXrci6hGyTF3xe8ncKSs2pXiiO0kqUnddjpj0iwJrv4Sq/WXH
zbAiRcGLAgMBAAECggEAMce+vh3sGPKBs67cPuA9EUsa0u6QmuQDOPJui2dqbati
bDhsSVLdtpWB+03WGHNWLBxgWdr8m6CvZgrWYE24dfua4td9Tf7lYWC7nAw3j2Hr
8iUhOdBaZj0Mlj042PFukbqmZk1dHtsL0V1B51HEiG9i/y4NSvNWsW8CqKGG8nJH
N2CjboXEx/aCrQhOkcSN0walGJRhOM75rBFixgj5jCZzAhYwlw5TR5NWS2i6ruuq
JvL1cUqeeyc/vHFU05WzAb5DM3Z+ZUhMZWZcReW9P8Kiku5c3UKoq41AiJxd/Gnq
6t2jhBSfvLwpjyu8AJrQTs/QKwv/wHXLdv9sUiOMKQKBgQDmWkDsIsCM6QNKA/lv
bMuzWyj2hr51Y4VHJjalOr7COInSbPsTfeosFVxJWjDL0E+0jz/9XTVJ3Jav8eG0
AofLRjOzFHODPRJeuUQQlG/oAGEvAm0rErRsTHxybcjc7wXr3wl+sCO/f+63yht0
c+FtmoyzEYRu7VP8OE4vcX0u2QKBgQDY2pvQv7gCpdFIlZqqX/9Zslbvm6oCb+Sw
j5+lX9/val/XQu335RkK32Mzfs+qHDUQPPSKObNjfggX/arJd2oJ18DFK7P5E+Jf
TOKqsEzgZS+PALIjZ+lBDtomArbVijacRIM3LsMi9CL2TcxhNAge6q1dwUopgjLw
6M3LAPi9AwKBgQCnuLNou+0DLG4OqFIoBUlUMF3lEjr+8hWKtpI3QEzA0bXYFy3B
BX9J1cu6RQcef3BpgZwP+JviSdEWDsJN9UG2ikj+bTemKQOFINQkVlAc1pnsRpIC
OL5R1GcQUktcQlVHZsBdFBcTSi0gePIAmpda3JrxjyGkOv1Zug2DkdiaEQKBgQDC
aOn78YUESqgfjI/GYp3ISkwKL+HwoWPCrmAPoK5gM1uM3qH89dTHnJGQ3wVJmlQw
JJWPPj+G2Lxk1bPBPl9AR764hX+ps5vkmEc1gyzIl65VY+hQOZ4yByCnpxNGycw/
uGRymmey9HBLpF+wXTdSkE2wmdLk96a3t96XOl3FBQKBgEnYliP4QoEXfhzngcuX
xUPPy8km16KvBEWhiLtrJKrh+UwXRcu4a7BlqOTP33LJMG7adgkquoSuhFgmxGQT
JZdTDJXfLanDEDMNTEVWPI0GccSs8krYSh5r04BVauP1eIdwqRxWk/q/2tiXPP0q
aKx50LwLmXANox+ruZI9LiGO
-----END PRIVATE KEY-----"""


# ---------------------------------------------------------------------------
# CASE 2: Placeholder value  -> EXPECTED: NOT DETECTED (low entropy)
# Repeated / dictionary content. Pattern-only scanners often false-positive
# here; entropy analysis filters it out.
# ==>> add entropy: 4.2 to the query so the false positve will be removed.
# ---------------------------------------------------------------------------
PLACEHOLDER_KEY = """-----BEGIN PRIVATE KEY-----
your-private-key-goes-here-your-private-key-goes-here-your-key
replace-me-replace-me-replace-me-replace-me-replace-me-replace
-----END PRIVATE KEY-----"""


# ---------------------------------------------------------------------------
# CASE 3: Example key inside a doc comment -> EXPECTED: FILTERED (test/example context)
# Contextual analysis recognizes example/sample usage.
# Sample only. Do not paste a real key here:
#   ssh_key = "-----BEGIN RSA PRIVATE KEY-----EXAMPLE...EXAMPLE-----END RSA PRIVATE KEY-----"
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# CASE 4: The SECURE pattern  -> EXPECTED: NOT DETECTED (no hardcoded secret)
# Key is pulled from an environment variable, not embedded in source.
# ---------------------------------------------------------------------------
def connect_secure(host):
    key_material = os.environ["DEPLOY_SSH_KEY"]
    pkey = paramiko.RSAKey.from_private_key(io.StringIO(key_material))
    client = paramiko.SSHClient()
    client.connect(hostname=host, username="deploy", pkey=pkey)
    return client


def connect_insecure(host):
    # Uses the hardcoded REAL_DEPLOY_KEY above. This is the anti-pattern
    # the scanner should catch and the developer should remediate.
    pkey = paramiko.RSAKey.from_private_key(io.StringIO(REAL_DEPLOY_KEY))
    client = paramiko.SSHClient()
    client.connect(hostname=host, username="deploy", pkey=pkey)
    return client


# ===========================================================================
# TOKEN-STYLE SECRETS (entropy + context discrimination)
# These are unstructured tokens with no PEM-style delimiters, so entropy is
# the primary signal that separates a real credential from a placeholder.
# All tokens below are synthetic and authenticate to nothing.
# ===========================================================================


# ---------------------------------------------------------------------------
# CASE 5: GitHub Personal Access Token  -> EXPECTED: DETECTED
# Recognized prefix (ghp_) + high-entropy 36-char body.
# ---------------------------------------------------------------------------
GITHUB_API_TOKEN = "ghp_irs9GRF95bIn1o8BTl2axoiezjitAJLIyelI"


# ---------------------------------------------------------------------------
# CASE 6: GitHub token placeholder  -> EXPECTED: NOT DETECTED (low entropy)
# Right prefix, but the body is obvious filler. Entropy filters it out.
# ---------------------------------------------------------------------------
GITHUB_API_TOKEN_PLACEHOLDER = "ghp_your_token_here_0000000000000000000"


# ---------------------------------------------------------------------------
# CASE 7: Jira / Atlassian API token  -> EXPECTED: DETECTED
# High-entropy Atlassian-style token used for Jira Cloud REST auth.
# ---------------------------------------------------------------------------
JIRA_API_TOKEN = "ATATTHh6aBdRyfQTbdN7MN24gWvCr"


# ---------------------------------------------------------------------------
# CASE 8: Jira token placeholder  -> EXPECTED: NOT DETECTED (low entropy)
# ---------------------------------------------------------------------------
JIRA_API_TOKEN_PLACEHOLDER = "ATATT-replace-with-your-jira-token"


def call_github_api(repo):
    # Hardcoded GITHUB_API_TOKEN above. Anti-pattern the scanner should catch.
    headers = {"Authorization": f"token {GITHUB_API_TOKEN}"}
    return headers, repo


def call_jira_api(issue):
    # Hardcoded JIRA_API_TOKEN above. Anti-pattern the scanner should catch.
    headers = {"Authorization": f"Bearer {JIRA_API_TOKEN}"}
    return headers, issue
