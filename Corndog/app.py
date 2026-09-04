"""
vuln_test_app.py

INTENTIONALLY VULNERABLE test fixture for Checkmarx One SAST scanner validation.
Do NOT deploy this. Do NOT expose it to a network. For scan-testing purposes only.

Contains:
  1. SQL Injection  - build_user_query() / get_user()
  2. Command Injection - ping_host()

Both take unsanitized input and pass it straight into a sink (SQL string
concatenation, os.system) so SAST should flag them as tainted data flows.
"""

import sqlite3
import os
import sys


def setup_db():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
    cur.execute("INSERT INTO users (username, email) VALUES ('alice', 'alice@example.com')")
    cur.execute("INSERT INTO users (username, email) VALUES ('bob', 'bob@example.com')")
    conn.commit()
    return conn


def get_user(conn, username):
    """
    VULNERABLE: SQL Injection (CWE-89)
    User-controlled 'username' is concatenated directly into the SQL string
    instead of using a parameterized query (e.g. cur.execute(query, (username,))).
    """
    cur = conn.cursor()
    query = "SELECT id, username, email FROM users WHERE username = '" + username + "'"
    cur.execute(query)
    return cur.fetchall()


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
    conn = setup_db()

    print("=== SQL Injection test ===")
    username = input("Enter a username to look up: ")
    results = get_user(conn, username)
    print("Results:", results)

    print("\n=== Command Injection test ===")
    host = input("Enter a host to ping: ")
    ping_host(host)


if __name__ == "__main__":
    main()
