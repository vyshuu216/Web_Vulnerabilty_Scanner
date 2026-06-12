"""
Database Manager
=================
Handles SQLite operations for storing and retrieving scan history.
All scan results are persisted locally in a SQLite database file.
"""

import sqlite3
import json
import os
from datetime import datetime

# Database file path — stored in the project root
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scans.db")


def init_db():
    """
    Initialize the SQLite database and create tables if they don't exist.
    Called once at application startup.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Main scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT NOT NULL,
            score       INTEGER NOT NULL,
            timestamp   TEXT NOT NULL,
            header_data TEXT,
            ssl_data    TEXT,
            port_data   TEXT,
            server_data TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_scan(
    url: str,
    score: int,
    header_results: dict,
    ssl_results: dict,
    port_results: dict,
    server_results: dict
) -> int:
    """
    Save a completed scan to the database.

    Args:
        url            : Target URL that was scanned.
        score          : Overall security score (0–100).
        header_results : HTTP header analysis output.
        ssl_results    : SSL inspection output.
        port_results   : Port scan output.
        server_results : Server analysis output.

    Returns:
        int: The auto-generated scan ID.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans (url, score, timestamp, header_data, ssl_data, port_data, server_data)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        score,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        json.dumps(header_results),
        json.dumps(ssl_results),
        json.dumps(port_results),
        json.dumps(server_results),
    ))

    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return scan_id


def get_scan_history(limit: int = 50) -> list:
    """
    Retrieve the most recent scans from the database.

    Args:
        limit: Maximum number of scan records to return.

    Returns:
        list: List of tuples (id, url, score, timestamp).
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, url, score, timestamp
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    return rows


def get_scan_by_id(scan_id: int) -> dict | None:
    """
    Retrieve a full scan record by its ID.

    Args:
        scan_id: The scan's database ID.

    Returns:
        dict: Full scan data including all module results, or None if not found.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, url, score, timestamp, header_data, ssl_data, port_data, server_data
        FROM scans
        WHERE id = ?
    """, (scan_id,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "url": row[1],
        "score": row[2],
        "timestamp": row[3],
        "header_results": json.loads(row[4]) if row[4] else {},
        "ssl_results": json.loads(row[5]) if row[5] else {},
        "port_results": json.loads(row[6]) if row[6] else {},
        "server_results": json.loads(row[7]) if row[7] else {},
    }


def delete_scan(scan_id: int) -> bool:
    """
    Delete a scan record from the database.

    Args:
        scan_id: The scan's database ID.

    Returns:
        bool: True if deletion was successful.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    deleted = cursor.rowcount > 0

    conn.commit()
    conn.close()

    return deleted
