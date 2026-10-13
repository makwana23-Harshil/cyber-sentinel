from database import db
from auth.middleware import hash_password
from datetime import datetime, timezone
from config import Config


ADMIN_NAME = Config.ADMIN_NAME
ADMIN_EMAIL = Config.ADMIN_EMAIL
ADMIN_PASSWORD = Config.ADMIN_PASSWORD


def create_admin():
    if not ADMIN_PASSWORD:
        raise RuntimeError("Set ADMIN_PASSWORD in backend/.env or the environment.")

    email = ADMIN_EMAIL.lower().strip()

    # Check whether admin already exists
    existing_admin = db.users.find_one({
        "email": email
    })

    if existing_admin:
        print("An account with this email already exists.")

        if existing_admin.get("role") == "admin":
            print("This account is already an admin.")
        else:
            print("This email belongs to a normal user.")
            print("No changes were made.")

        return

    now = datetime.now(timezone.utc)

    admin = {
        "name": ADMIN_NAME,
        "email": email,
        "password_hash": hash_password(ADMIN_PASSWORD),
        "role": "admin",
        "is_active": True,
        "created_at": now,
        "last_login": now,
        "total_scans": 0
    }

    result = db.users.insert_one(admin)

    print("\n===================================")
    print("       ADMIN CREATED SUCCESSFULLY")
    print("===================================")
    print(f"ID       : {result.inserted_id}")
    print(f"Name     : {ADMIN_NAME}")
    print(f"Email    : {ADMIN_EMAIL}")
    print("Role     : admin")
    print("Status   : Active")
    print("===================================\n")


if __name__ == "__main__":
    create_admin()