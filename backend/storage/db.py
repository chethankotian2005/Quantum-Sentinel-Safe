import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Any

from models.schemas import ScanResult

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sentinel.db")

def init_db():
    """Initializes the SQLite database schema."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            target_id TEXT NOT NULL,
            score INTEGER,
            grade TEXT,
            critical_count INTEGER,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER,
            full_json TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_scan(target_id: str, scan: ScanResult):
    """Saves a ScanResult to the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    # Store timestamp and target_id inside the scan result too
    scan.target_id = target_id
    scan.timestamp = timestamp
    
    score = scan.risk_score.score if scan.risk_score else 0
    grade = scan.risk_score.grade if scan.risk_score else 'Unknown'
    critical = scan.risk_score.critical_count if scan.risk_score else 0
    high = scan.risk_score.high_count if scan.risk_score else 0
    medium = scan.risk_score.medium_count if scan.risk_score else 0
    low = scan.risk_score.low_count if scan.risk_score else 0
    
    # Need to dump the pydantic model to json string
    full_json = scan.json()
    
    cursor.execute('''
        INSERT OR REPLACE INTO scans 
        (scan_id, timestamp, target_id, score, grade, critical_count, high_count, medium_count, low_count, full_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        scan.scan_id, 
        timestamp, 
        target_id, 
        score, 
        grade, 
        critical, 
        high, 
        medium, 
        low, 
        full_json
    ))
    
    conn.commit()
    conn.close()

def get_scan_history(target_id: str) -> List[Dict[str, Any]]:
    """Retrieves the history of scans for a given target, sorted chronologically."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT scan_id, timestamp, target_id, score, grade, critical_count, high_count, medium_count, low_count 
        FROM scans 
        WHERE target_id = ? 
        ORDER BY timestamp ASC
    ''', (target_id,))
    
    rows = cursor.fetchall()
    conn.close()
    
    history = []
    for row in rows:
        history.append(dict(row))
        
    return history
