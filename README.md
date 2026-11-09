# RBAC Platform

User and role management with Casbin RBAC.

```
Browser -> Next.js pages + API routes :3000 -> Go gateway :8080 -> FastAPI :8000 -> MySQL
           (only published port)               (internal)         (internal)
```

- **Next.js** is the only API the browser calls. It keeps the JWT in an httpOnly cookie and checks permissions on the server before rendering a page or forwarding a request.
- **Go gateway** handles login, validates the JWT, enforces Casbin on every request and proxies to FastAPI.
- **FastAPI** holds the user business logic.
- **MySQL** stores users, roles and Casbin policies (`casbin_rule`).

## Setup

```bash
cp .env.example .env          # then replace every value
docker compose up --build -d
docker compose run --rm gateway /app/seed
```

Open http://localhost:3000 and sign in with `SYSTEM_ADMIN_EMAIL` and `SYSTEM_ADMIN_PASSWORD`.

The seed is the only way to create a system-admin. It does nothing if one already exists. All other users are created in the app.

## Permissions

| API | Casbin obj / act | system-admin | super-admin | admin | user |
|---|---|---|---|---|---|
| `GET /api/users` | users / list | any | any | any | no |
| `GET /api/users/:id` | users / read | any | any | any | no |
| `GET /api/me` | me / read | any | any | any | any |
| `PATCH /api/users/:id/info` | user_info / update | any | any | no | own |
| `PATCH /api/users/:id/company` | company_info / update | any | any | any | no |
| `POST /api/users/:id/deactivate` | users / deactivate | any | no | no | no |
| `POST /api/users` | users / create | any | any | no | no |
| `PUT /api/users/:id/role` | user_role / assign | any | any | no | no |
| `GET /api/roles` | roles / list | any | any | no | no |
| `POST /api/roles` | roles / create | any | any | no | no |

`POST /api/auth/login` and `POST /api/auth/logout` are public.

### Additional rules

- `system-admin` can't be set through `createUser` or `assignRole`, and a system-admin's role can't be changed.
- Only a system-admin can update the info or company of a system-admin.
- Nobody can deactivate themselves or change their own role.
- Custom roles can only be given the permissions returned by `GET /api/roles` as `grantable`, and always get `me / read`. Deactivation and role management can't be granted.

Policies are loaded when the gateway starts. API changes apply immediately; after editing `casbin_rule` by hand, restart the gateway.

## Tests

```bash
cd gateway && go test ./...

cd api && python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
PYTHONPATH=. .venv/bin/pytest

# End to end, against the running app on a development database. Creates test data.
set -a; source .env; set +a; python3 scripts/e2e.py
```
# casbin-go-fastapi
