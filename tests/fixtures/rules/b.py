from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_credentials=True)  # BAD:cors-wildcard-with-credentials
app.add_middleware(CORSMiddleware, allow_origins=["https://x.com"], allow_credentials=True)
def u(name, cur, session, r, d):
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")   # BAD:python-sql-string-building
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)  # BAD:python-sql-string-building
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
    session.execute(text(f"DELETE FROM t WHERE id={name}"))      # BAD:python-sql-string-building
    r.keys("session:*")                                          # BAD:redis-keys-command
    d.keys()
    r.flushdb()                                                  # BAD:redis-flush-in-code
    session.execute(text("SELECT * FROM t WHERE id = :id"), {"id": name})
SECRET_KEY = "super-secret-value"                                # BAD:hardcoded-secret-key
DATABASE_URL = "postgresql+asyncpg://user:hunter22@localhost/db" # BAD:hardcoded-database-url-credentials
REDIS_URL = "redis://localhost:6379/0"
flask_app.run(host="0.0.0.0", debug=True)                        # BAD:flask-debug-enabled
flask_app.run(host="0.0.0.0")
