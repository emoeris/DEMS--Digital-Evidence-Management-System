# DEMS: Secure Digital Evidence Management System

A fully local system for ingesting, storing, verifying and tracking digital evidence with a tamper-evident chain of custody. No cloud services.

| Layer | Stack |
|---|---|
| Backend | Python 3.11+, FastAPI, SQLAlchemy 2.0 async, SQLite (swappable to PostgreSQL) |
| Security | AES-256-GCM at rest, envelope-encrypted keys (Argon2id KEK), Argon2id passwords, JWT + rotating refresh tokens, TOTP MFA, hash-chained custody and audit logs |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Zustand, Axios |

---

## 1. Folder structure

Extract the project so you end up with **one** `dems` folder that contains `backend` and `frontend` side by side:

```
dems/                              <- open THIS folder in VS Code
├── README.md                      (this file)
├── .gitignore
│
├── backend/                       <- run all Python commands from here
│   ├── requirements.txt
│   ├── .env.example               (copy to .env, then edit)
│   ├── pytest.ini
│   ├── app/
│   │   ├── main.py                FastAPI app factory
│   │   ├── api/
│   │   │   ├── deps.py            auth + role guards
│   │   │   └── routes/            auth, cases, evidence, custody, audit
│   │   ├── core/                  config.py, crypto.py, security.py
│   │   ├── db/                    models.py, session.py
│   │   ├── schemas/               Pydantic request/response models
│   │   └── services/              business logic (evidence, auth, cases, audit, chain)
│   ├── scripts/
│   │   └── create_admin.py        creates the first administrator
│   └── tests/                     139 pytest tests
│
└── frontend/                      <- run all npm commands from here
    ├── package.json
    ├── vite.config.ts             dev server on :5173, proxies /api -> :8000
    ├── tailwind.config.ts
    ├── index.html
    └── src/
        ├── main.tsx, App.tsx
        ├── index.css              design tokens + glass styles
        ├── lib/                   api.ts, crypto.ts, utils.ts, useAsync.ts
        ├── store/auth.ts
        ├── components/            layout/AppShell.tsx, ui/
        └── pages/                 Login, Dashboard, Cases, Audit
```

These folders are created on first run and are **not** part of the download. They are git-ignored:
`backend/.venv/`, `backend/.env`, `backend/dems.db`, `backend/vault/`, `backend/keyconfig.json`, `frontend/node_modules/`, `frontend/dist/`.

### Extracting the zip

1. Pick a parent folder for your projects, for example `C:\Projects` or `~/projects`.
2. Extract `dems-phase2c.zip` **into that parent folder**. The zip already contains the top-level `dems` folder.
3. Check that you did not create a nested `dems/dems`. On Windows, "Extract All" suggests a destination ending in `\dems-phase2c`. Change it to your parent folder, or move the inner `dems` folder up one level afterwards.
4. In VS Code choose **File → Open Folder → dems**.

If you downloaded files one by one, put each at the same relative path shown in the tree above (for example `evidence_service.py` goes in `backend/app/services/`). Every folder under `backend/app/` and `backend/tests/` needs an empty `__init__.py`, which the zip already contains.

---

## 2. Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Python | 3.11 or newer | `python --version` |
| Node.js | 18.18 or newer (20 LTS recommended) | `node --version` |
| libmagic | any | needed by `python-magic` for file-type checks |

Install libmagic:

- **Windows:** `pip install python-magic-bin` (after activating the venv, step 3.1)
- **macOS:** `brew install libmagic`
- **Ubuntu/Debian:** `sudo apt install libmagic1`

---

## 3. First-time setup

Use two terminals in VS Code (Terminal → New Terminal, then the split icon).

### 3.1 Backend (terminal 1)

```bash
cd backend
python -m venv .venv

# activate the virtual environment
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux

pip install -r requirements.txt
```

In VS Code, select `backend/.venv` as the Python interpreter (Ctrl+Shift+P → "Python: Select Interpreter").

Create your settings file:

```bash
copy .env.example .env          # Windows
cp .env.example .env            # macOS / Linux
```

Edit `backend/.env` and replace the two placeholder values. The app refuses to start while they still contain `change-me`.

```bash
# generate a SECRET_KEY:
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

- `SECRET_KEY`: the value you just generated.
- `KEK_PASSPHRASE`: a long passphrase (12+ characters) that protects all evidence keys.

> **Back up your passphrase and `keyconfig.json`.** Evidence is encrypted with keys derived from the passphrase. If you lose either one, **the evidence cannot be recovered.** `keyconfig.json` is created on first start in `backend/`. Keep a copy of it, and the passphrase, somewhere safe (separately from each other).

Create the first administrator (registration is admin-only, so this one is made from the command line):

```bash
python -m scripts.create_admin --username admin --email admin@example.org
```

You will be asked for a temporary password (12+ characters). On first sign-in the web app asks you to choose a new one. Use the same `KEK_PASSPHRASE` here as in `.env`.

Run the tests (optional but recommended):

```bash
python -m pytest
```

### 3.2 Frontend (terminal 2)

```bash
cd frontend
npm install
```

---

## 4. Running the app

Start both servers (each in its own terminal):

```bash
# terminal 1: backend, from dems/backend with the venv active
uvicorn app.main:create_app --factory --port 8000

# terminal 2: frontend, from dems/frontend
npm run dev
```

| URL | What |
|---|---|
| http://localhost:5173 | The web app. **Open this one.** |
| http://localhost:8000/docs | Interactive API docs (development mode only) |
| http://localhost:8000/health | Backend health check |

Sign in with the admin account you created. Then, as the administrator, create investigator and auditor accounts (API: `POST /auth/register`, via `/docs`; a user-management screen is not built yet).

Port 5173 is fixed on purpose: the backend's CORS allow-list is locked to it. If the port is busy, Vite will exit with an error instead of picking another.

Optional local HTTPS: install [mkcert](https://github.com/FiloSottile/mkcert), run `mkcert localhost` inside a new `frontend/certs/` folder (it creates `localhost.pem` and `localhost-key.pem`). Vite then switches to HTTPS automatically. Add `https://localhost:5173` to `CORS_ORIGINS`, which is already in the default list.

---

## 5. Roles

| Role | Can do |
|---|---|
| **Administrator** | Manage users; create, update, close and delete empty cases; assign investigators; view all metadata, custody and audit logs; soft-delete evidence; verify integrity. Cannot upload, and can download evidence only for cases they are assigned to. |
| **Investigator** | Create cases; upload, download and verify evidence in cases they are **assigned to**; view those cases' custody chain. |
| **Auditor** | Read-only: all cases, custody chains and the audit log; verify integrity and chains. No evidence content, no uploads, no changes. |

Every action, including denials, is written to a hash-chained audit log. Evidence activity is also written to a per-case chain of custody.

---

## 6. Configuration reference (`backend/.env`)

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | none (required) | Signs JWTs. At least 32 characters. |
| `KEK_PASSPHRASE` | none | Derives the key-encryption key. **Leave empty in production:** the server then prompts for it at startup so it is never stored. |
| `ENVIRONMENT` | `development` | `production` enforces HTTPS origins, `REQUIRE_ADMIN_MFA=true`, strong Argon2 settings, and hides `/docs`. |
| `DATABASE_URL` | `sqlite+aiosqlite:///./dems.db` | Database (async driver required). |
| `VAULT_PATH` | `./vault` | Where encrypted evidence files live (directory mode 0700). |
| `KEY_CONFIG_PATH` | `./keyconfig.json` | Salt and parameters for key derivation. **Back this up.** |
| `ACCESS_TOKEN_TTL` / `REFRESH_TOKEN_TTL` | `900` / `604800` | Token lifetimes in seconds (15 minutes / 7 days). |
| `CORS_ORIGINS` | `https://localhost:5173,http://localhost:5173` | Comma-separated, no wildcards. |
| `REQUIRE_ADMIN_MFA` | `false` | Admins must complete TOTP MFA before using the API. |
| `MAX_LOGIN_ATTEMPTS` | `5` | Failed logins before progressive lockout. |
| `UPLOAD_MAX_BYTES` | `2147483648` | Per-file size limit (2 GB). |
| `VERIFY_BEFORE_DOWNLOAD` | `true` | Re-check integrity before every download. |
| `ALLOWED_MIME_TYPES` | broad forensic list | Detected file types accepted (`type/*` wildcards allowed). |

---

## 7. API quick reference

| Area | Endpoints |
|---|---|
| Auth | `POST /auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/register` (admin), `/auth/change-password`, `/auth/mfa/enroll`, `/auth/mfa/verify`, `GET /auth/me` |
| Cases | `GET/POST /cases`, `GET/PATCH/DELETE /cases/{id}`, `POST /cases/{id}/close`, `/cases/{id}/assignments`, `GET /cases/{id}/evidence` |
| Evidence | `POST /evidence/upload`, `GET /evidence/{id}/metadata`, `GET /evidence/{id}/download`, `POST /evidence/{id}/verify`, `DELETE /evidence/{id}` (admin, soft delete) |
| Custody | `GET /custody/{case_id}`, `GET /custody/{case_id}/verify` |
| Audit | `GET /audit`, `GET /audit/verify` (admin, auditor) |

The browser calls these under `/api/...`; the Vite dev proxy strips the prefix.

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `ValidationError ... SECRET_KEY` on startup | You left `change-me` in `.env`, or `.env` is missing. Run the backend from the `backend/` folder. |
| `InvalidPassphraseError` | `KEK_PASSPHRASE` does not match the one `keyconfig.json` was created with. |
| `Vault directory ... insecure permissions` | macOS/Linux: `chmod 700 backend/vault`. |
| `ImportError: failed to find libmagic` | Install libmagic (section 2). |
| `Port 5173 is already in use` | Close the other process; the port is fixed. |
| Web app shows "Cannot reach the server" | The backend is not running on port 8000. |
| Locked out after failed logins | Wait for the lockout to expire (starts at 15 minutes) or have an admin investigate. |
| Fresh start | Stop the backend, delete `backend/dems.db*`, `backend/vault/` and `backend/keyconfig.json`, then re-run `create_admin`. **This destroys all data and keys.** |

---

## 9. Known limitations

- **Large uploads and temp files:** the multipart parser spools files larger than 1 MB to the system temp folder in plaintext before encryption. Point the temp folder at an encrypted or restricted location until a streaming upload path is added.
- **No per-IP rate limiting:** only per-account lockout exists.
- **Chain tail truncation:** removing the newest events of a chain cannot be detected from the chain alone. Compare `head_hash` with a stored checkpoint.
- **Schema management:** tables are created automatically at startup (`create_all`). Alembic migrations, including the append-only triggers, are not set up yet.
- **Refresh token storage:** the browser keeps it in `sessionStorage` (cleared when the tab closes). An HttpOnly cookie would be stronger and needs a backend change.
- **Fonts:** Inter loads from Google Fonts. For an air-gapped machine, self-host it with `@fontsource/inter`.
- **Frontend scope:** sign-in (with MFA and forced password change), overview, case list and audit log exist. Evidence upload/download screens, case detail and user management are not built yet; the API and the hashing and upload helpers (`frontend/src/lib/`) are ready for them.
