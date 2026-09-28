"""
Deletes the existing taskpay.db so the next run of app.py rebuilds it
from schema.sql (this is what fixes "no such table: users").

WARNING: this deletes all existing accounts/tasks/data in taskpay.db.
Run it once from the same folder as app.py, then start app.py normally.

Usage:
    python reset_db.py
"""
import os

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "taskpay.db")

removed = False
for path in (DB_PATH, DB_PATH + "-journal", DB_PATH + "-wal", DB_PATH + "-shm"):
    if os.path.exists(path):
        os.remove(path)
        print(f"Deleted {path}")
        removed = True

if not removed:
    print("No existing taskpay.db found — nothing to delete.")

print("Done. Start app.py now; it will detect no DB and run init_db() "
      "to recreate all tables (including users) and seed the admin account.")
