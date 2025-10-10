#!/usr/bin/env python3
"""
Database Synchronization Script for NetOps Tools

This script scans all models in app/models.py and ensures all tables
exist in the database. It will create any missing tables without
affecting existing data.

Usage:
    python sync_database.py

Features:
    - Automatically discovers all models
    - Creates missing tables
    - Shows detailed report of changes
    - Safe to run multiple times (idempotent)
    - Does not modify existing table structures
"""

import os
import sys
from datetime import datetime

# Add the parent directory to the path so we can import app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from sqlalchemy import inspect, MetaData
from sqlalchemy.exc import OperationalError


def get_all_model_tables():
    """Get all table names defined in models."""
    tables = {}
    # Get all subclasses of db.Model (compatible with SQLAlchemy 2.x)
    try:
        # SQLAlchemy 2.x
        for mapper in db.Model.registry.mappers:
            model_class = mapper.class_
            if hasattr(model_class, '__tablename__'):
                tables[model_class.__tablename__] = model_class
    except AttributeError:
        # SQLAlchemy 1.x fallback
        for name, obj in db.Model._decl_class_registry.items():
            if name != '_sa_module_registry' and hasattr(obj, '__tablename__'):
                tables[obj.__tablename__] = obj
    return tables


def get_existing_tables(engine):
    """Get all tables that currently exist in the database."""
    inspector = inspect(engine)
    return set(inspector.get_table_names())


def print_header(text):
    """Print a formatted header."""
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80)


def print_section(text):
    """Print a formatted section."""
    print(f"\n--- {text} ---")


def create_missing_tables(app):
    """
    Create any missing tables in the database.

    Returns:
        tuple: (created_tables, existing_tables, total_tables)
    """
    with app.app_context():
        # Get all model tables
        model_tables = get_all_model_tables()
        total_tables = len(model_tables)

        # Get existing tables
        try:
            existing_tables = get_existing_tables(db.engine)
        except OperationalError as e:
            print(f"❌ Error connecting to database: {e}")
            return None, None, None

        # Find missing tables
        model_table_names = set(model_tables.keys())
        missing_tables = model_table_names - existing_tables

        return missing_tables, existing_tables, model_tables


def main():
    """Main function to sync database tables."""
    print_header("NetOps Tools - Database Synchronization")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Create Flask app
    try:
        app = create_app()
        print("✓ Flask application initialized")
    except Exception as e:
        print(f"❌ Failed to initialize Flask app: {e}")
        return 1

    with app.app_context():
        # Get database info
        print(f"✓ Database: {db.engine.url}")

        print_section("Analyzing Database Schema")

        # Get all model tables
        model_tables = get_all_model_tables()
        print(f"Found {len(model_tables)} models defined in app/models.py:")
        for i, table_name in enumerate(sorted(model_tables.keys()), 1):
            print(f"  {i:2d}. {table_name}")

        # Get existing tables
        try:
            existing_tables = get_existing_tables(db.engine)
            print(f"\nFound {len(existing_tables)} existing tables in database:")
            for i, table_name in enumerate(sorted(existing_tables), 1):
                print(f"  {i:2d}. {table_name}")
        except OperationalError as e:
            print(f"❌ Error connecting to database: {e}")
            return 1

        # Find missing tables
        model_table_names = set(model_tables.keys())
        missing_tables = model_table_names - existing_tables
        extra_tables = existing_tables - model_table_names

        print_section("Analysis Results")

        if missing_tables:
            print(f"\n⚠️  Missing tables ({len(missing_tables)}):")
            for i, table_name in enumerate(sorted(missing_tables), 1):
                model_class = model_tables[table_name]
                print(f"  {i}. {table_name} ({model_class.__name__})")
        else:
            print("✓ No missing tables - database is in sync!")

        if extra_tables:
            print(f"\nℹ️  Extra tables not in models ({len(extra_tables)}):")
            for i, table_name in enumerate(sorted(extra_tables), 1):
                print(f"  {i}. {table_name}")
            print("  Note: These might be migration tables or legacy tables")

        # Create missing tables
        if missing_tables:
            print_section("Creating Missing Tables")

            response = input("\nDo you want to create the missing tables? (yes/no): ")
            if response.lower() not in ['yes', 'y']:
                print("Aborted by user.")
                return 0

            try:
                # Create only the missing tables
                print("\nCreating tables...")
                metadata = MetaData()

                # Reflect all tables from models
                for table_name in missing_tables:
                    model_class = model_tables[table_name]
                    print(f"  • Creating {table_name} ({model_class.__name__})... ", end="")

                    # Get the table from the model
                    table = model_class.__table__
                    table.create(db.engine, checkfirst=True)
                    print("✓")

                print_header("SUCCESS - Tables Created")
                print(f"\n✓ Successfully created {len(missing_tables)} table(s)")
                print(f"\nCreated tables:")
                for i, table_name in enumerate(sorted(missing_tables), 1):
                    print(f"  {i}. {table_name}")

            except Exception as e:
                print(f"\n❌ Error creating tables: {e}")
                print("\nTroubleshooting:")
                print("  1. Check database permissions")
                print("  2. Verify database connection")
                print("  3. Check for conflicting migrations")
                print("  4. Review error logs")
                return 1

        # Summary
        print_section("Summary")
        print(f"\nTotal models defined:    {len(model_tables)}")
        print(f"Existing tables:         {len(existing_tables)}")
        print(f"Missing tables:          {len(missing_tables)}")
        print(f"Extra tables:            {len(extra_tables)}")
        print(f"\nDatabase status:         {'✓ IN SYNC' if not missing_tables else '⚠️  OUT OF SYNC'}")

        print_header("Database Synchronization Complete")
        print(f"Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
