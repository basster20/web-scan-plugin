#!/usr/bin/env python3
"""
local_bible.py - Query NKJV and Yoruba Bible translations from local SQLite database.

This module provides functions to:
- Fetch verses by reference (book, chapter, verse)
- Support verse ranges
- Handle missing translations gracefully
- Map English book names to Yoruba equivalents
"""

import sqlite3
import os
import json
import logging
from typing import Optional, List, Tuple, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bible_dual.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
DB_PATH = os.path.join(PROJECT_DIR, "bible.db")
BOOK_ALIASES_PATH = os.path.join(SCRIPT_DIR, "data", "book_aliases.json")


class BibleDatabase:
    """Handles all database operations for Bible verse lookups."""
    
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.aliases = self._load_aliases()
        self._connection: Optional[sqlite3.Connection] = None
    
    def _load_aliases(self) -> Dict[str, Dict[str, str]]:
        """Load English <-> Yoruba book name mappings."""
        try:
            with open(BOOK_ALIASES_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load book aliases: {e}")
            return {"english_to_yoruba": {}, "yoruba_to_english": {}}
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._connection is None:
            if not os.path.exists(self.db_path):
                raise FileNotFoundError(f"Bible database not found: {self.db_path}")
            self._connection = sqlite3.connect(self.db_path)
            self._connection.row_factory = sqlite3.Row
        return self._connection
    
    def close(self):
        """Close database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None
    
    def get_english_book_name(self, book_name: str) -> Optional[str]:
        """
        Convert any book name (English or Yoruba) to canonical English name.
        
        Args:
            book_name: Book name in English or Yoruba
            
        Returns:
            Canonical English book name or None if not found
        """
        # Normalize input
        book_name = book_name.strip()
        
        # Check if it's already an English name (case-insensitive)
        eng_to_yor = self.aliases.get('english_to_yoruba', {})
        for eng_name in eng_to_yor.keys():
            if eng_name.lower() == book_name.lower():
                return eng_name
        
        # Check if it's a Yoruba name
        yor_to_eng = self.aliases.get('yoruba_to_english', {})
        for yor_name, eng_name in yor_to_eng.items():
            if yor_name.lower() == book_name.lower():
                return eng_name
        
        # Try direct match in database
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Check NKJV table
        cursor.execute(
            "SELECT DISTINCT book FROM nkjv WHERE LOWER(book) = LOWER(?)",
            (book_name,)
        )
        result = cursor.fetchone()
        if result:
            return result['book']
        
        # Check Yoruba table
        cursor.execute(
            "SELECT DISTINCT book FROM yoruba WHERE LOWER(book) = LOWER(?)",
            (book_name,)
        )
        result = cursor.fetchone()
        if result:
            # Try to map to English
            yor_name = result['book']
            if yor_name in yor_to_eng:
                return yor_to_eng[yor_name]
            return yor_name
        
        return None
    
    def get_yoruba_book_name(self, english_book: str) -> str:
        """
        Get Yoruba equivalent of an English book name.
        
        Args:
            english_book: English book name
            
        Returns:
            Yoruba book name or the English name if no mapping exists
        """
        eng_to_yor = self.aliases.get('english_to_yoruba', {})
        return eng_to_yor.get(english_book, english_book)
    
    def get_verse(self, book: str, chapter: int, verse: int) -> Dict[str, Any]:
        """
        Fetch a single verse in both NKJV and Yoruba.
        
        Args:
            book: Book name (English or Yoruba)
            chapter: Chapter number
            verse: Verse number
            
        Returns:
            Dictionary with keys: 'reference', 'nkjv', 'yoruba', 'english_book', 'yoruba_book'
        """
        # Resolve book name to English
        english_book = self.get_english_book_name(book)
        
        if not english_book:
            logger.warning(f"Book not found: {book}")
            return {
                'reference': f"{book} {chapter}:{verse}",
                'nkjv': None,
                'yoruba': None,
                'english_book': book,
                'yoruba_book': book,
                'error': f"Book '{book}' not found"
            }
        
        yoruba_book = self.get_yoruba_book_name(english_book)
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        result = {
            'reference': f"{english_book} • {yoruba_book} {chapter}:{verse}",
            'nkjv': None,
            'yoruba': None,
            'english_book': english_book,
            'yoruba_book': yoruba_book,
            'chapter': chapter,
            'verse': verse
        }
        
        # Fetch NKJV
        cursor.execute(
            "SELECT text FROM nkjv WHERE book = ? AND chapter = ? AND verse = ?",
            (english_book, chapter, verse)
        )
        nkjv_row = cursor.fetchone()
        if nkjv_row:
            result['nkjv'] = nkjv_row['text']
        else:
            logger.warning(f"NKJV verse not found: {english_book} {chapter}:{verse}")
            result['nkjv'] = "[Translation missing]"
        
        # Fetch Yoruba
        cursor.execute(
            "SELECT text FROM yoruba WHERE book = ? AND chapter = ? AND verse = ?",
            (yoruba_book, chapter, verse)
        )
        yoruba_row = cursor.fetchone()
        if yoruba_row:
            result['yoruba'] = yoruba_row['text']
        else:
            logger.warning(f"Yoruba verse not found: {yoruba_book} {chapter}:{verse}")
            result['yoruba'] = "[Translation missing]"
        
        return result
    
    def get_verse_range(self, book: str, chapter: int, start_verse: int, end_verse: int) -> List[Dict[str, Any]]:
        """
        Fetch a range of verses in both NKJV and Yoruba.
        
        Args:
            book: Book name (English or Yoruba)
            chapter: Chapter number
            start_verse: Starting verse number
            end_verse: Ending verse number
            
        Returns:
            List of verse dictionaries
        """
        verses = []
        
        for v in range(start_verse, end_verse + 1):
            verse_data = self.get_verse(book, chapter, v)
            verses.append(verse_data)
        
        return verses
    
    def get_chapter(self, book: str, chapter: int) -> List[Dict[str, Any]]:
        """
        Fetch an entire chapter in both NKJV and Yoruba.
        
        Args:
            book: Book name (English or Yoruba)
            chapter: Chapter number
            
        Returns:
            List of verse dictionaries for the entire chapter
        """
        # Resolve book name
        english_book = self.get_english_book_name(book)
        
        if not english_book:
            return [{
                'reference': f"{book} {chapter}",
                'nkjv': None,
                'yoruba': None,
                'error': f"Book '{book}' not found"
            }]
        
        yoruba_book = self.get_yoruba_book_name(english_book)
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Get all verses for this chapter from NKJV
        cursor.execute(
            "SELECT verse, text FROM nkjv WHERE book = ? AND chapter = ? ORDER BY verse",
            (english_book, chapter)
        )
        nkjv_verses = {row['verse']: row['text'] for row in cursor.fetchall()}
        
        # Get all verses for this chapter from Yoruba
        cursor.execute(
            "SELECT verse, text FROM yoruba WHERE book = ? AND chapter = ? ORDER BY verse",
            (yoruba_book, chapter)
        )
        yoruba_verses = {row['verse']: row['text'] for row in cursor.fetchall()}
        
        # Combine results
        all_verses = set(nkjv_verses.keys()) | set(yoruba_verses.keys())
        
        verses = []
        for v in sorted(all_verses):
            verse_data = {
                'reference': f"{english_book} • {yoruba_book} {chapter}:{v}",
                'nkjv': nkjv_verses.get(v, "[Translation missing]"),
                'yoruba': yoruba_verses.get(v, "[Translation missing]"),
                'english_book': english_book,
                'yoruba_book': yoruba_book,
                'chapter': chapter,
                'verse': v
            }
            verses.append(verse_data)
        
        if not verses:
            logger.warning(f"Chapter not found: {english_book} {chapter}")
            verses.append({
                'reference': f"{english_book} {chapter}",
                'nkjv': None,
                'yoruba': None,
                'error': f"Chapter {chapter} not found in {english_book}"
            })
        
        return verses
    
    def search_available_books(self) -> Dict[str, List[str]]:
        """
        Get list of available books in each translation.
        
        Returns:
            Dictionary with keys 'nkjv' and 'yoruba', each containing list of book names
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT DISTINCT book FROM nkjv ORDER BY book")
        nkjv_books = [row['book'] for row in cursor.fetchall()]
        
        cursor.execute("SELECT DISTINCT book FROM yoruba ORDER BY book")
        yoruba_books = [row['book'] for row in cursor.fetchall()]
        
        return {
            'nkjv': nkjv_books,
            'yoruba': yoruba_books
        }
    
    def verify_database(self) -> Dict[str, Any]:
        """
        Verify database integrity and return statistics.
        
        Returns:
            Dictionary with database statistics
        """
        if not os.path.exists(self.db_path):
            return {'error': 'Database file not found'}
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) as count FROM nkjv")
            nkjv_count = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM yoruba")
            yoruba_count = cursor.fetchone()['count']
            
            return {
                'ok': True,
                'nkjv_verses': nkjv_count,
                'yoruba_verses': yoruba_count,
                'db_path': self.db_path
            }
        except Exception as e:
            return {'error': str(e)}


# Singleton instance for easy access
_bible_db: Optional[BibleDatabase] = None


def get_bible_db() -> BibleDatabase:
    """Get or create the Bible database singleton."""
    global _bible_db
    if _bible_db is None:
        _bible_db = BibleDatabase()
    return _bible_db


def close_bible_db():
    """Close the Bible database connection."""
    global _bible_db
    if _bible_db:
        _bible_db.close()
        _bible_db = None


if __name__ == "__main__":
    # Test the database
    print("Testing Bible Database...")
    
    db = get_bible_db()
    
    # Verify database
    stats = db.verify_database()
    print(f"Database status: {stats}")
    print()
    
    # Test fetching a verse
    print("Testing John 3:16...")
    verse = db.get_verse("John", 3, 16)
    print(f"Reference: {verse['reference']}")
    print(f"NKJV: {verse['nkjv']}")
    print(f"Yoruba: {verse['yoruba']}")
    print()
    
    # Test with Yoruba book name
    print("Testing with Yoruba book name 'Johanu'...")
    verse = db.get_verse("Johanu", 3, 16)
    print(f"Reference: {verse['reference']}")
    print()
    
    close_bible_db()
    print("Test complete.")
