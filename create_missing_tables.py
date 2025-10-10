#!/usr/bin/env python3
"""
Quick script to create missing database tables.

This script creates any missing tables without prompting.
Safe to run multiple times.

Usage:
    python create_missing_tables.py
"""

import os
import sys

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from sqlalchemy import inspect


def main():
    print("=" * 60)
    print("  Creating Missing Database Tables")
    print("=" * 60)

    # Create Flask app
    app = create_app()

    with app.app_context():
        print(f"\nDatabase: {db.engine.url}")

        # Get existing tables
        inspector = inspect(db.engine)
        existing_tables = set(inspector.get_table_names())

        # Get all model tables
        model_tables = {}
        for name, obj in db.Model._decl_class_registry.items():
            if name != '_sa_module_registry' and hasattr(obj, '__tablename__'):
                model_tables[obj.__tablename__] = obj

        # Find missing tables
        model_table_names = set(model_tables.keys())
        missing_tables = model_table_names - existing_tables

        print(f"\nTotal models: {len(model_tables)}")
        print(f"Existing tables: {len(existing_tables)}")
        print(f"Missing tables: {len(missing_tables)}")

        if not missing_tables:
            print("\n✓ All tables exist - nothing to do!")
            return 0

        print(f"\nCreating {len(missing_tables)} missing table(s):")
        for table_name in sorted(missing_tables):
            model_class = model_tables[table_name]
            print(f"  • {table_name} ({model_class.__name__})... ", end="", flush=True)
            try:
                model_class.__table__.create(db.engine, checkfirst=True)
                print("✓")
            except Exception as e:
                print(f"✗ Error: {e}")
                return 1

        print("\n" + "=" * 60)
        print(f"  ✓ Successfully created {len(missing_tables)} table(s)")
        print("=" * 60)

        print("\nCreated tables:")
        for i, table_name in enumerate(sorted(missing_tables), 1):
            print(f"  {i}. {table_name}")

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nAborted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
