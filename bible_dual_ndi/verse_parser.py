#!/usr/bin/env python3
"""
verse_parser.py - Parse Bible verse references from text or voice input.

Supports formats like:
- "John 3:16"
- "Psalm 23"
- "Ezra 3:10-12"
- "1 Corinthians 13"
- "Johanu 3:16" (Yoruba book names)
- "Show me Ezra 3:10" (natural language)
"""

import re
import logging
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class VerseReference:
    """Represents a parsed Bible verse reference."""
    book: str
    chapter: int
    start_verse: Optional[int] = None
    end_verse: Optional[int] = None
    is_chapter_only: bool = False
    
    def __str__(self) -> str:
        if self.is_chapter_only:
            return f"{self.book} {self.chapter}"
        elif self.end_verse and self.end_verse != self.start_verse:
            return f"{self.book} {self.chapter}:{self.start_verse}-{self.end_verse}"
        else:
            return f"{self.book} {self.chapter}:{self.start_verse}"


class VerseParser:
    """Parse Bible verse references from natural language input."""
    
    # Common Bible book name patterns (English and Yoruba)
    # Order matters - longer names should come first
    BOOK_PATTERNS = [
        # English books (with numbers)
        r"1\s*Corinthians", r"2\s*Corinthians",
        r"1\s*Thessalonians", r"2\s*Thessalonians",
        r"1\s*Timothy", r"2\s*Timothy",
        r"1\s*Peter", r"2\s*Peter",
        r"1\s*John", r"2\s*John", r"3\s*John",
        r"1\s*Samuel", r"2\s*Samuel",
        r"1\s*Kings", r"2\s*Kings",
        r"1\s*Chronicles", r"2\s*Chronicles",
        r"Song\s+of\s+Solomon",
        
        # Yoruba books (with numbers)
        r"1\s*[Kk]orinti", r"2\s*[Kk]orinti",
        r"1\s*[Tt]esalonika", r"2\s*[Tt]esalonika",
        r"1\s*[Tt]imotiu", r"2\s*[Tt]imotiu",
        r"1\s*[Pp]iteru", r"2\s*[Pp]iteru",
        r"1\s*[Jj]ohanu", r"2\s*[Jj]ohanu", r"3\s*[Jj]ohanu",
        r"1\s*[Ss]amu[ẹe]li", r"2\s*[Ss]amu[ẹe]li",
        r"1\s*[Oo]bakunrin", r"2\s*[Oo]bakunrin",
        r"1\s*[Oo]jo\s+[Ii]we-Akọọlẹ", r"2\s*[Oo]jo\s+[Ii]we-Akọọlẹ",
        
        # Single word books (English)
        r"Genesis", r"Exodus", r"Leviticus", r"Numbers", r"Deuteronomy",
        r"Joshua", r"Judges", r"Ruth", r"Samuel", r"Kings", r"Chronicles",
        r"Ezra", r"Nehemiah", r"Esther", r"Job", r"Psalms", r"Psalm",
        r"Proverbs", r"Ecclesiastes", r"Isaiah", r"Jeremiah", r"Lamentations",
        r"Ezekiel", r"Daniel", r"Hosea", r"Joel", r"Amos", r"Obadiah",
        r"Jonah", r"Micah", r"Nahum", r"Habakkuk", r"Zephaniah", r"Haggai",
        r"Zechariah", r"Malachi", r"Matthew", r"Mark", r"Luke", r"John",
        r"Acts", r"Romans", r"Galatians", r"Ephesians", r"Philippians",
        r"Colossians", r"Thessalonians", r"Timothy", r"Titus", r"Philemon",
        r"Hebrews", r"James", r"Peter", r"Jude", r"Revelation",
        
        # Single word books (Yoruba)
        r"[Gg]enesisi", r"[Ee]ksodu", r"[Ll]evitikus", r"[Nn]umeri", r"[Dd]euteronomi",
        r"[Jj]osua", r"[Aa]dajo", r"[Rr]utu", r"[Ss]amu[ẹe]li", r"[Oo]bakunrin",
        r"[Ee]sra", r"[Nn]ehemia", r"[Ee]steri", r"[Jj]obu", r"[Ss]aamu",
        r"[Oo]we", r"[Oo]kòwè", r"[Aa]isaia", r"[Jj]eremia", r"[Ss]unu",
        r"[Ee]sekieli", r"[Dd]ani[ẹe]li", r"[Hh]osea", r"[Jj]oeli", r"[Aa]mosi",
        r"[Oo]badia", r"[Jj]ona", r"[Mm]ika", r"[Nn]ahumu", r"[Hh]abakuki",
        r"[Ss]efania", r"[Hh]agai", r"[Ss]ekaria", r"[Mm]alaki", r"[Mm]atteu",
        r"[Mm]arku", r"[Ll]uku", r"[Jj]ohanu", r"[Ii][Ṣṣ]e", r"[Rr]omu",
        r"[Kk]orinti", r"[Gg]alatia", r"[Ee]fesu", r"[Ff]ilipi", r"[Kk]olosse",
        r"[Tt]esalonika", r"[Tt]imotiu", r"[Tt]itu", r"[Ff]ilemoni", r"[Hh]eberu",
        r"[Jj]akobu", r"[Pp]iteru", r"[Jj]udu", r"[Ii]fihan",
    ]
    
    def __init__(self):
        # Build combined pattern for book names
        self.book_pattern = re.compile(
            r'\b(' + '|'.join(self.BOOK_PATTERNS) + r')\b',
            re.IGNORECASE
        )
        
        # Pattern for chapter:verse or chapter:verse-end_verse
        self.verse_pattern = re.compile(
            r'(\d+)\s*:\s*(\d+)(?:\s*-\s*(\d+))?',
            re.IGNORECASE
        )
        
        # Pattern for chapter only (just a number after book name)
        self.chapter_pattern = re.compile(
            r'\b(\d+)\b',
            re.IGNORECASE
        )
    
    def parse(self, text: str) -> Optional[VerseReference]:
        """
        Parse a Bible verse reference from text.
        
        Args:
            text: Input text containing a verse reference
            
        Returns:
            VerseReference object or None if parsing fails
        """
        if not text or not isinstance(text, str):
            return None
        
        text = text.strip()
        logger.debug(f"Parsing: '{text}'")
        
        # Find book name
        book_match = self.book_pattern.search(text)
        if not book_match:
            logger.warning(f"No book name found in: '{text}'")
            return None
        
        book_name = book_match.group(1)
        # Normalize book name (standard capitalization)
        book_name = self._normalize_book_name(book_name)
        logger.debug(f"Found book: '{book_name}'")
        
        # Get the text after the book name
        after_book = text[book_match.end():].strip()
        
        # Try to find chapter:verse pattern
        verse_match = self.verse_pattern.search(after_book)
        
        if verse_match:
            chapter = int(verse_match.group(1))
            start_verse = int(verse_match.group(2))
            end_verse = int(verse_match.group(3)) if verse_match.group(3) else None
            
            ref = VerseReference(
                book=book_name,
                chapter=chapter,
                start_verse=start_verse,
                end_verse=end_verse,
                is_chapter_only=False
            )
            logger.info(f"Parsed reference: {ref}")
            return ref
        
        # Try to find chapter-only pattern (number right after book)
        chapter_match = self.chapter_pattern.match(after_book)
        if chapter_match:
            chapter = int(chapter_match.group(1))
            
            ref = VerseReference(
                book=book_name,
                chapter=chapter,
                start_verse=None,
                end_verse=None,
                is_chapter_only=True
            )
            logger.info(f"Parsed chapter reference: {ref}")
            return ref
        
        logger.warning(f"Could not parse chapter/verse from: '{text}'")
        return None
    
    def _normalize_book_name(self, name: str) -> str:
        """Normalize book name to standard capitalization."""
        # Common mappings for normalization
        normalizations = {
            'psalms': 'Psalms',
            'psalm': 'Psalms',
            'saamu': 'Psalms',
            'genesisi': 'Genesis',
            'eksodu': 'Exodus',
            'levitikus': 'Leviticus',
            'numeri': 'Numbers',
            'deuteronomi': 'Deuteronomy',
            'josua': 'Joshua',
            'adajo': 'Judges',
            'rutu': 'Ruth',
            'samuẹli': 'Samuel',
            'samuẹli': 'Samuel',
            'obakunrin': 'Kings',
            'ojo iwe-akọọlẹ': 'Chronicles',
            'esra': 'Ezra',
            'nehemia': 'Nehemiah',
            'esteri': 'Esther',
            'jobu': 'Job',
            'owe': 'Proverbs',
            'okòwè': 'Ecclesiastes',
            'aisaia': 'Isaiah',
            'jeremia': 'Jeremiah',
            'sunu': 'Lamentations',
            'esekieli': 'Ezekiel',
            'daniẹli': 'Daniel',
            'hosea': 'Hosea',
            'joeli': 'Joel',
            'amosi': 'Amos',
            'obadia': 'Obadiah',
            'jona': 'Jonah',
            'mika': 'Micah',
            'nahumu': 'Nahum',
            'habakuki': 'Habakkuk',
            'sefania': 'Zephaniah',
            'hagai': 'Haggai',
            'sekaria': 'Zechariah',
            'malaki': 'Malachi',
            'matteu': 'Matthew',
            'marku': 'Mark',
            'luku': 'Luke',
            'johanu': 'John',
            'iṣe': 'Acts',
            'ise': 'Acts',
            'romu': 'Romans',
            'korinti': 'Corinthians',
            'galatia': 'Galatians',
            'efesu': 'Ephesians',
            'filipi': 'Philippians',
            'kolosse': 'Colossians',
            'tesalonika': 'Thessalonians',
            'timotiu': 'Timothy',
            'titu': 'Titus',
            'filemoni': 'Philemon',
            'heberu': 'Hebrews',
            'jakobu': 'James',
            'piteru': 'Peter',
            'judu': 'Jude',
            'ifihan': 'Revelation',
        }
        
        name_lower = name.lower().strip()
        
        # Check for exact match
        if name_lower in normalizations:
            return normalizations[name_lower]
        
        # Check with spaces normalized
        name_normalized = ' '.join(name_lower.split())
        if name_normalized in normalizations:
            return normalizations[name_normalized]
        
        # Return original with title case
        return name.title()
    
    def extract_references(self, text: str) -> List[VerseReference]:
        """
        Extract all Bible verse references from text.
        
        Args:
            text: Input text that may contain multiple references
            
        Returns:
            List of VerseReference objects
        """
        references = []
        
        # Simple approach: try to parse the entire text first
        ref = self.parse(text)
        if ref:
            references.append(ref)
        
        # If no reference found, try to find multiple references
        if not references:
            # Look for patterns like "John 3:16 and Romans 8:28"
            # This is a simplified implementation
            pass
        
        return references


def parse_verse_reference(text: str) -> Optional[VerseReference]:
    """
    Convenience function to parse a verse reference.
    
    Args:
        text: Input text containing a verse reference
        
    Returns:
        VerseReference object or None
    """
    parser = VerseParser()
    return parser.parse(text)


if __name__ == "__main__":
    # Test the parser
    parser = VerseParser()
    
    test_cases = [
        "John 3:16",
        "Psalm 23",
        "Ezra 3:10-12",
        "1 Corinthians 13",
        "Show me Ezra 3:10",
        "Johanu 3:16",
        "Saamu 23",
        "Matteu 5:3-12",
        "Please display Genesis 1:1",
        "Romans 8:28",
        "Filipi 4:13",
    ]
    
    print("Testing Verse Parser")
    print("=" * 50)
    
    for test in test_cases:
        result = parser.parse(test)
        if result:
            print(f"✓ '{test}' => {result}")
        else:
            print(f"✗ '{test}' => Failed to parse")
    
    print("=" * 50)
    print("Test complete.")
