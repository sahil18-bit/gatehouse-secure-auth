# Gatehouse: secure sign-up and sign-in demo

React + TypeScript frontend (Vite) and a Python (Flask) backend.

## Run it

Backend (terminal 1):

    cd backend
    pip install -r requirements.txt
    python app.py            # http://127.0.0.1:5000

Frontend (terminal 2):

    cd frontend
    npm install
    npm run dev              # http://localhost:5173

The Vite dev server proxies `/api` to Flask, so no CORS setup is needed.

## Where each step lives (backend/app.py)

| Step | Requirement | Location |
|---|---|---|
| 1 | Import `hashlib`, `re` | top of file |
| 2 | Accept registration details | `POST /api/register` |
| 3 | Validate inputs | `validate_inputs()` |
| 4 | Password strength: Weak, Moderate, Strong | `check_strength()`, `POST /api/strength` |
| 5 | Generate a password hash | `hash_password()` (salted PBKDF2-HMAC-SHA256 via `hashlib`) |
| 6 | Register the user | `USERS` dict stores username, salt, hash |
| 7 | Accept login credentials | `POST /api/login` |
| 8 | Verify password | recompute hash, compare with `hmac.compare_digest` |
| 9 | Authenticate | "Login Successful" / "Login Failed" |
| 10 | Monitor failed attempts | alert at 3 failures, 30 s lock at 5 |
| 11 | OWASP awareness | `GET /api/owasp` (OWASP Top 10:2025) |
| 12 | AI security | `GET /api/ai-security` |
| 13 | Final security status | `GET /api/status` and the dark Security status panel |

## Notes for going beyond a demo

- Storage is in memory. Use a database with parameterised queries.
- Serve over HTTPS and issue sessions or tokens after login (this demo does not).
- Prefer Argon2id, scrypt, or bcrypt in production. PBKDF2 is used here because it ships with `hashlib`.
- The live strength meter sends the password to the server as you type. That is fine on localhost; in production compute the preview in the browser.
- `/api/status` is public so you can see alerts. Protect it in a real system.
- Rate-limit by IP as well as by username.
