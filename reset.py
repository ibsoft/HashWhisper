import argparse
import os
import shutil
import sys
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError


def wipe_database(engine):
    desired = [
        "message_reactions",
        "media_blobs",
        "presence_events",
        "integrity_chain",
        "messages",
        "group_memberships",
        "chat_groups",
        "users",
    ]
    with engine.begin() as conn:
        existing = {
            row[0]
            for row in conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public';")
            )
        }
        targets = [t for t in desired if t in existing]
        if not targets:
            print("No target tables found to truncate.")
            return
        sql = f"TRUNCATE TABLE {', '.join(targets)} RESTART IDENTITY CASCADE;"
        conn.execute(text(sql))


def wipe_storage(storage_path: Path):
    if not storage_path.exists():
        return
    for child in storage_path.iterdir():
        if child.is_file():
            child.unlink(missing_ok=True)
        elif child.is_dir():
            shutil.rmtree(child, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Wipe HashWhisper data (Postgres).")
    parser.add_argument("--yes", action="store_true", help="Confirm destructive wipe.")
    parser.add_argument(
        "--delete-storage",
        action="store_true",
        help="Also delete encrypted upload blobs (UPLOAD_FOLDER).",
    )
    args = parser.parse_args()

    if not args.yes:
        print("Refusing to run without --yes")
        sys.exit(1)

    db_uri = os.environ.get("HASHWHISPER_DATABASE_URI")
    if not db_uri:
        print("HASHWHISPER_DATABASE_URI is not set. Aborting.")
        sys.exit(1)
    if not db_uri.startswith("postgres"):
        print("This reset script is intended for Postgres only. Aborting.")
        sys.exit(1)

    try:
        engine = create_engine(db_uri)
        wipe_database(engine)
        print("Database tables truncated and sequences reset.")
    except SQLAlchemyError as exc:
        print(f"Database wipe failed: {exc}")
        sys.exit(1)

    if args.delete_storage:
        storage_root = Path(os.environ.get("HASHWHISPER_UPLOAD_FOLDER", "app/storage"))
        wipe_storage(storage_root)
        print(f"Storage cleared: {storage_root}")

    print("Reset complete.")


if __name__ == "__main__":
    main()
