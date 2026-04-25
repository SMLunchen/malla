"""
Database connection management for Meshtastic Mesh Health Web UI.
"""

import logging
import os
import sqlite3

# Prefer configuration loader over environment variables
from malla.config import get_config

logger = logging.getLogger(__name__)


_PRAGMA_DONE: set[str] = set()  # tracks which db paths have had one-time PRAGMAs applied


def get_db_connection() -> sqlite3.Connection:
    """
    Get a connection to the SQLite database with proper concurrency configuration.

    Returns:
        sqlite3.Connection: Database connection with row factory set and WAL mode enabled
    """
    db_path: str = (
        os.getenv("MALLA_DATABASE_FILE")
        or get_config().database_file
        or "meshtastic_history.db"
    )

    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row

        cursor = conn.cursor()

        # Per-connection PRAGMAs (must run every time)
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA cache_size=-51200")   # 50 MB page cache
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.execute("PRAGMA mmap_size=268435456") # 256 MB memory-mapped I/O

        # One-time PRAGMAs + schema work — only on first connection per db_path per process
        if db_path not in _PRAGMA_DONE:
            cursor.execute("PRAGMA journal_mode=WAL")  # persistent once set, but harmless
            try:
                _ensure_schema_migrations(cursor)
            except Exception as e:
                logger.warning(f"Schema migration check failed: {e}")
            _PRAGMA_DONE.add(db_path)

        return conn
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        raise


def init_database() -> None:
    """
    Initialize the database connection and verify it's accessible.
    This function is called during application startup.
    """
    # Resolve DB path:
    # 1. Explicit override via `MALLA_DATABASE_FILE` env-var (handy for scripts)
    # 2. Value from YAML configuration
    # 3. Fallback to hard-coded default

    db_path: str = (
        os.getenv("MALLA_DATABASE_FILE")
        or get_config().database_file
        or "meshtastic_history.db"
    )

    logger.info(f"Initializing database connection to: {db_path}")

    try:
        # Test the connection
        conn = get_db_connection()

        # Test a simple query to verify the database is accessible
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
        table_count = cursor.fetchone()[0]

        # Check and log the journal mode
        cursor.execute("PRAGMA journal_mode")
        journal_mode = cursor.fetchone()[0]

        conn.close()

        logger.info(
            f"Database connection successful - found {table_count} tables, journal_mode: {journal_mode}"
        )

    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        # Don't raise the exception - let the app start anyway
        # The database might not exist yet or be created by another process


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------


_SCHEMA_MIGRATIONS_DONE: set[str] = set()


def _ensure_schema_migrations(cursor: sqlite3.Cursor) -> None:
    """Run any idempotent schema updates that the application depends on.

    Currently this checks that ``node_info`` has a ``primary_channel`` column
    (added in April 2024) so queries that reference it do not fail when the
    database was created with an older version of the schema.

    The function is **safe** to run repeatedly – it will only attempt each
    migration once per Python process and each individual migration is
    guarded with a try/except that ignores the *duplicate column* error.
    """

    global _SCHEMA_MIGRATIONS_DONE  # pylint: disable=global-statement

    # Quickly short-circuit if we've already handled migrations in this process
    if "primary_channel" in _SCHEMA_MIGRATIONS_DONE:
        return

    try:
        # Check whether the column already exists
        cursor.execute("PRAGMA table_info(node_info)")
        columns = [row[1] for row in cursor.fetchall()]

        if "primary_channel" not in columns:
            cursor.execute("ALTER TABLE node_info ADD COLUMN primary_channel TEXT")
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_node_primary_channel ON node_info(primary_channel)"
            )
            logging.info(
                "Added primary_channel column to node_info table via auto-migration"
            )

        _SCHEMA_MIGRATIONS_DONE.add("primary_channel")
    except sqlite3.OperationalError as exc:
        # Ignore errors about duplicate columns in race situations – another
        # process may have altered the table first.
        if "duplicate column name" in str(exc).lower():
            _SCHEMA_MIGRATIONS_DONE.add("primary_channel")
        else:
            raise

    try:
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_packet_gateway_mesh ON packet_history(mesh_packet_id, gateway_id, timestamp)"
        )
    except Exception as e:
        logger.warning(f"Failed to create idx_packet_gateway_mesh: {e}")

    try:
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_packet_position_lookup ON packet_history(from_node_id, timestamp) WHERE portnum = 3 AND raw_payload IS NOT NULL"
        )
    except Exception as e:
        logger.warning(f"Failed to create idx_packet_position_lookup: {e}")

    try:
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_packet_portnum_name ON packet_history(portnum_name)"
        )
    except Exception as e:
        logger.warning(f"Failed to create idx_packet_portnum_name: {e}")

    # Covering index for dashboard all-time count + recent stats (avoids full row reads)
    try:
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_packet_ts_node_rssi ON packet_history(timestamp, from_node_id, rssi, snr, processed_successfully)"
        )
    except Exception as e:
        logger.warning(f"Failed to create idx_packet_ts_node_rssi: {e}")

    # Covering index for gateway distribution query
    try:
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_packet_ts_gateway_success ON packet_history(timestamp, gateway_id, processed_successfully)"
        )
    except Exception as e:
        logger.warning(f"Failed to create idx_packet_ts_gateway_success: {e}")
