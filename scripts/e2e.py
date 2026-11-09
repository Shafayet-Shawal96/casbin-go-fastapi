#!/usr/bin/env python3
"""End-to-end permission checks against the running app, through the Next.js API.

Usage: BASE_URL=http://localhost:3000 SYSTEM_ADMIN_EMAIL=... SYSTEM_ADMIN_PASSWORD=... python3 scripts/e2e.py

Each run creates new users and a new role, so it can be repeated. Run it against
a development database only.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("BASE_URL", "http://localhost:3000")
ADMIN_EMAIL = os.environ["SYSTEM_ADMIN_EMAIL"]
ADMIN_PASSWORD = os.environ["SYSTEM_ADMIN_PASSWORD"]
PASSWORD = "e2e-password-123"
RUN = str(int(time.time()))

failures = 0
passes = 0


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


opener = urllib.request.build_opener(NoRedirect)


class Client:
    def __init__(self):
        self.cookie = None
        self.id = None

    def call(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(BASE + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        try:
            res = opener.open(req)
        except urllib.error.HTTPError as err:
            res = err
        raw = res.read().decode()
        for header in res.headers.get_all("Set-Cookie") or []:
            if header.startswith("session="):
                self.cookie = header.split(";", 1)[0]
        try:
            return res.status if hasattr(res, "status") else res.code, json.loads(raw)
        except json.JSONDecodeError:
            return res.status if hasattr(res, "status") else res.code, raw

    def login(self, email, password):
        status, body = self.call("POST", "/api/auth/login", {"email": email, "password": password})
        if status == 200:
            self.id = self.call("GET", "/api/me")[1]["id"]
        return status, body


def check(label, actual, expected):
    global failures, passes
    if actual == expected:
        passes += 1
    else:
        failures += 1
        print(f"FAIL {label}: got {actual}, want {expected}")


def new_user(role, tag):
    return {"email": f"{tag}-{RUN}@example.com", "password": PASSWORD, "name": tag, "role": role}


sys_admin = Client()
status, _ = sys_admin.login(ADMIN_EMAIL, ADMIN_PASSWORD)
if status != 200:
    sys.exit(f"system-admin login failed with {status}; has the seed run?")


def create_logged_in(role, tag):
    status, body = sys_admin.call("POST", "/api/users", new_user(role, tag))
    check(f"create {role}", status, 201)
    client = Client()
    check(f"login {role}", client.login(body["email"], PASSWORD)[0], 200)
    return client


def create_target(tag):
    status, body = sys_admin.call("POST", "/api/users", new_user("user", tag))
    check(f"create target {tag}", status, 201)
    return body["id"]


super_admin = create_logged_in("super-admin", "super")
admin = create_logged_in("admin", "admin")
user = create_logged_in("user", "user")
actors = {"system-admin": sys_admin, "super-admin": super_admin, "admin": admin, "user": user}

# Permission table. Order of expected values: system-admin, super-admin, admin, user.
target = create_target("target")
for i, (name, method, path, body, expected) in enumerate(
    [
        ("getallusers", "GET", "/api/users", None, (200, 200, 200, 403)),
        ("getuser", "GET", f"/api/users/{target}", None, (200, 200, 200, 403)),
        ("me", "GET", "/api/me", None, (200, 200, 200, 200)),
        ("updateuserinfo", "PATCH", f"/api/users/{target}/info", {"phone": "1"}, (200, 200, 403, 403)),
        ("updatecompany", "PATCH", f"/api/users/{target}/company", {"department": "D"}, (200, 200, 200, 403)),
        ("assignrole", "PUT", f"/api/users/{target}/role", {"role": "user"}, (200, 200, 403, 403)),
    ]
):
    for (role, client), want in zip(actors.items(), expected):
        check(f"{name} as {role}", client.call(method, path, body)[0], want)

for (role, client), want in zip(actors.items(), (200, 403, 403, 403)):
    victim = create_target(f"victim-{role}")
    check(f"deactivate as {role}", client.call("POST", f"/api/users/{victim}/deactivate")[0], want)

for (role, client), want in zip(actors.items(), (201, 201, 403, 403)):
    check(f"createuser as {role}", client.call("POST", "/api/users", new_user("user", f"made-{role}"))[0], want)

permission = {"obj": "users", "act": "list", "scope": "any"}
for (role, client), want in zip(actors.items(), (201, 201, 403, 403)):
    body = {"name": f"e2e-{role}-{RUN}", "permissions": [permission]}
    check(f"createrole as {role}", client.call("POST", "/api/roles", body)[0], want)

# Own-scope rules.
check("user edits own info", user.call("PATCH", f"/api/users/{user.id}/info", {"phone": "2"})[0], 200)
check("user edits another", user.call("PATCH", f"/api/users/{target}/info", {"phone": "2"})[0], 403)
check("user edits own company", user.call("PATCH", f"/api/users/{user.id}/company", {"department": "X"})[0], 403)

# System-admin protection.
for role, client in (("system-admin", sys_admin), ("super-admin", super_admin)):
    check(f"{role} creates system-admin", client.call("POST", "/api/users", new_user("system-admin", f"x-{role}"))[0], 403)
    check(f"{role} assigns system-admin", client.call("PUT", f"/api/users/{target}/role", {"role": "system-admin"})[0], 403)
check("super changes system-admin role", super_admin.call("PUT", f"/api/users/{sys_admin.id}/role", {"role": "user"})[0], 403)
check("super edits system-admin info", super_admin.call("PATCH", f"/api/users/{sys_admin.id}/info", {"phone": "3"})[0], 403)
check("admin edits system-admin company", admin.call("PATCH", f"/api/users/{sys_admin.id}/company", {"department": "X"})[0], 403)

# Self-protection.
check("super changes own role", super_admin.call("PUT", f"/api/users/{super_admin.id}/role", {"role": "user"})[0], 403)
check("system-admin deactivates self", sys_admin.call("POST", f"/api/users/{sys_admin.id}/deactivate")[0], 403)

# createRole limits.
for obj, act in (("users", "deactivate"), ("users", "create"), ("user_role", "assign"), ("roles", "create"), ("roles", "list")):
    body = {"name": f"bad-{RUN}", "permissions": [{"obj": obj, "act": act, "scope": "any"}]}
    check(f"grant {obj}/{act}", super_admin.call("POST", "/api/roles", body)[0], 422)
body = {"name": "admin", "permissions": [permission]}
check("create role with built-in name", super_admin.call("POST", "/api/roles", body)[0], 409)

# Custom role applies immediately.
role_name = f"auditor-{RUN}"
check("create auditor", super_admin.call("POST", "/api/roles", {"name": role_name, "permissions": [permission]})[0], 201)
auditor = create_logged_in("user", "auditor")
check("auditor before role", auditor.call("GET", "/api/users")[0], 403)
check("assign auditor", sys_admin.call("PUT", f"/api/users/{auditor.id}/role", {"role": role_name})[0], 200)
check("auditor granted", auditor.call("GET", "/api/users")[0], 200)
check("auditor ungranted", auditor.call("GET", f"/api/users/{target}")[0], 403)

# Spoofed identity headers are ignored; responses have no password data.
status, body = user.call("GET", "/api/me")
check("me is own user", body["id"], user.id)
check("no password data", "password" in json.dumps(sys_admin.call("GET", "/api/users")[1]), False)

# Deactivation applies to an existing session.
doomed = create_logged_in("user", "doomed")
check("doomed before", doomed.call("GET", "/api/me")[0], 200)
check("deactivate doomed", sys_admin.call("POST", f"/api/users/{doomed.id}/deactivate")[0], 200)
check("doomed session", doomed.call("GET", "/api/me")[0], 401)
check("doomed login", Client().login(f"doomed-{RUN}@example.com", PASSWORD)[0], 401)

# Page authorization runs on the Next.js server.
anonymous = Client()
check("anonymous API", anonymous.call("GET", "/api/users")[0], 401)
check("anonymous page redirects", anonymous.call("GET", "/users")[0], 307)
check("user page is refused", user.call("GET", "/users")[0], 307)
check("admin page allowed", admin.call("GET", "/users")[0], 200)
check("admin new-user page refused", admin.call("GET", "/users/new")[0], 307)

print(f"{passes} passed, {failures} failed")
sys.exit(1 if failures else 0)
