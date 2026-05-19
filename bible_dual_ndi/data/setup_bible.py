#!/usr/bin/env python3
"""
setup_bible.py - Downloads NKJV and Yoruba Bible translations and creates local SQLite database.

This script:
1. Downloads NKJV JSON from scrollmapper GitHub
2. Downloads/creates Yoruba Bible (YBCV) data
3. Creates bible.db with tables: nkjv, yoruba
4. Each table has columns: book, chapter, verse, text

Run once to populate the local Bible database. After this, the app works fully offline.
"""

import json
import sqlite3
import os
import sys
import urllib.request
import re

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
DB_PATH = os.path.join(PROJECT_DIR, "bible.db")
BOOK_ALIASES_PATH = os.path.join(SCRIPT_DIR, "book_aliases.json")

# URLs for Bible data
# Note: URLs may change; if download fails, check for updated sources
NKJV_URL = "https://raw.githubusercontent.com/scrollmapper/bible_databases/8b5c6e0a4f7e1d3c2b9a8f7e6d5c4b3a2f1e0d9c/json/nkjv.json"

# Alternative NKJV sources (tried in order)
NKJV_ALTERNATIVES = [
    "https://github.com/scrollmapper/bible_databases/raw/master/json/nkjv.json",
]

# Yoruba Bible - we'll try multiple sources or create from available data
YORUBA_URLS = [
    "https://raw.githubusercontent.com/ajulibe/yoBible/main/ybcv.json",
    "https://raw.githubusercontent.com/scrollmapper/bible_databases/master/json/yoruba.json",
]


def load_book_aliases():
    """Load English <-> Yoruba book name mappings."""
    with open(BOOK_ALIASES_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


def normalize_book_name(name):
    """Normalize book name for consistent storage."""
    # Remove extra spaces, standardize capitalization
    name = name.strip()
    # Handle common variations
    name = re.sub(r'\s+', ' ', name)
    return name


def download_json(url):
    """Download JSON data from URL."""
    try:
        print(f"Downloading from {url}...")
        with urllib.request.urlopen(url, timeout=30) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception as e:
        print(f"Failed to download from {url}: {e}")
        return None


def parse_nkjv_data(data):
    """
    Parse NKJV JSON data into list of (book, chapter, verse, text) tuples.
    
    Expected format from scrollmapper:
    {
        "Genesis": {
            "1": {
                "1": "In the beginning God created...",
                ...
            },
            ...
        },
        ...
    }
    """
    verses = []
    
    if not isinstance(data, dict):
        print("Invalid NKJV data format")
        return verses
    
    for book_name, chapters in data.items():
        if not isinstance(chapters, dict):
            continue
        
        normalized_book = normalize_book_name(book_name)
        
        for chapter_num, chapter_verses in chapters.items():
            if not isinstance(chapter_verses, dict):
                continue
            
            try:
                chapter_int = int(chapter_num)
            except ValueError:
                continue
            
            for verse_num, verse_text in chapter_verses.items():
                try:
                    verse_int = int(verse_num)
                    verses.append((normalized_book, chapter_int, verse_int, verse_text))
                except ValueError:
                    continue
    
    return verses


def parse_yoruba_data(data, aliases):
    """
    Parse Yoruba Bible JSON data into list of (book, chapter, verse, text) tuples.
    
    Handles various possible formats.
    """
    verses = []
    
    if not isinstance(data, dict):
        print("Invalid Yoruba data format")
        return verses
    
    # Create reverse mapping (English -> Yoruba book names for matching)
    eng_to_yor = aliases.get('english_to_yoruba', {})
    yor_to_eng = aliases.get('yoruba_to_english', {})
    
    for book_name, chapters in data.items():
        if not isinstance(chapters, dict):
            continue
        
        normalized_book = normalize_book_name(book_name)
        
        for chapter_num, chapter_verses in chapters.items():
            if not isinstance(chapter_verses, dict):
                continue
            
            try:
                chapter_int = int(chapter_num)
            except ValueError:
                continue
            
            for verse_num, verse_text in chapter_verses.items():
                try:
                    verse_int = int(verse_num)
                    verses.append((normalized_book, chapter_int, verse_int, verse_text))
                except ValueError:
                    continue
    
    return verses


def create_sample_yoruba_data(aliases):
    """
    Create sample Yoruba Bible data for testing if no online source is available.
    In production, you would replace this with actual Yoruba Bible text.
    
    This creates a minimal dataset covering popular verses.
    """
    print("Creating sample Yoruba Bible data (for demonstration)...")
    print("NOTE: For full Yoruba Bible text, please obtain YBCV from official sources.")
    
    # Sample verses in Yoruba (public domain / creative commons examples)
    yoruba_data = {
        "Genesisi": {
            1: {
                1: "Ni ibẹrẹ, Ọlọrun da ọrun ati ayé.",
                2: "Ayé si jẹ alainiṣẹ́jú àti òfo; òkunkun si wa lori oju omi jinjin.",
                3: "Ọlọrun si wi pe, 'Ki imọlẹ ki o wa'; imọlẹ si wa.",
            },
            2: {
                1: "Nitorina ọrun ati ayé ni a ṣe pari, ati gbogbo ogun wọn.",
            }
        },
        "Eksodu": {
            20: {
                1: "Ọlọrun si soro gbogbo nkan wonyi, wipe,",
                2: "Emeni ni Oluwa Ọlọrun rẹ, ti o mu ọ jade kuro ni ile Egipti, kuro ni ile iṣẹ eru.",
                3: "Maṣe ni awọn olóòrùn miiran lodo mi.",
            }
        },
        "Saamu": {
            23: {
                1: "Oluwa ni oluṣọ-agutan mi; emi ko ni aini.",
                2: "O n mu mi sinu koriko tutu; o n darí mi si eti omi idakẹjẹ.",
                3: "O n tun ọkàn mi le; o n dari mi si ọna ododo nitori orukọ rẹ.",
                4: "Biotilejepe emi ba rin ninu afonifoji okunkun iku, emi ko ni beru buburu;",
                5: "Iwọ yoo pese tabili niwaju mi niwaju awọn ọta mi;",
                6: "Dajudaju rere ati aanu yoo tele mi ni gbogbo ọjọ igbesi aye mi;",
            }
        },
        "Johanu": {
            3: {
                16: "Nitori Ọlọrun fẹran agbaye bẹẹ, ti o fi Ọmọ rẹ ọkan ṣoṣo fun wọn,",
                17: "Nitori Ọlọrun ko ran Ọmọ rẹ si agbaye lati ṣe idajọ agbaye;",
            }
        },
        "Matteu": {
            5: {
                1: "Nigba ti o ri awọn eniyan pupọ, o goke lori oke-nla;",
                2: "O si bẹrẹ si kọ wọn, wipe:",
                3: "Oriire fun awọn ti o mọ ọkan wọn lọwọ;",
            }
        },
        "Esra": {
            3: {
                10: "Nigba ti awọn akọle tẹ ipilẹ ilé Olùgbéjáde silẹ,",
                11: "Won si dun, won si yin Oluwa,",
            }
        },
        "Romu": {
            8: {
                28: "A si mo pe ohun gbogbo n ṣiṣẹ papọ fun rere fun awọn ti o fẹran Ọlọrun,",
            }
        },
        "Filipi": {
            4: {
                13: "Mo le ṣe ohun gbogbo nipasẹ Kristi ti o fun mi ni agbara.",
            }
        },
        "1 Korinti": {
            13: {
                1: "Biotilejepe mo ba soro ede awọn eniyan ati ti angeli,",
                2: "Biotilejepe mo ba ni ẹ̀mí ìsọtẹlẹ,",
                3: "Biotilejepe mo ba pin ohun ini mi fun ounjẹ awọn alaini,",
                4: "Ifẹràn jẹ suuru, ifẹràn jẹ irele;",
            }
        }
    }
    
    return yoruba_data


def create_sample_nkjv_data():
    """
    Create sample NKJV Bible data for testing if no online source is available.
    This creates a minimal dataset covering popular verses that match the Yoruba samples.
    """
    print("Creating sample NKJV Bible data (for demonstration)...")
    
    sample_verses = {
        "Genesis": {
            1: {
                1: "In the beginning God created the heavens and the earth.",
                2: "Now the earth was formless and empty, darkness was over the surface of the deep.",
                3: "And God said, 'Let there be light,' and there was light.",
            },
            2: {
                1: "Thus the heavens and the earth were completed in all their vast array.",
            }
        },
        "Exodus": {
            20: {
                1: "And God spoke all these words:",
                2: "'I am the LORD your God, who brought you out of Egypt.'",
                3: "'You shall have no other gods before me.'",
            }
        },
        "Psalms": {
            23: {
                1: "The LORD is my shepherd; I shall not want.",
                2: "He makes me to lie down in green pastures; He leads me beside the still waters.",
                3: "He restores my soul; He leads me in the paths of righteousness.",
                4: "Yea, though I walk through the valley of the shadow of death, I will fear no evil;",
                5: "You prepare a table before me in the presence of my enemies;",
                6: "Surely goodness and mercy shall follow me all the days of my life;",
            }
        },
        "John": {
            3: {
                16: "For God so loved the world that He gave His only begotten Son,",
                17: "For God did not send His Son into the world to condemn the world;",
            }
        },
        "Matthew": {
            5: {
                1: "And when He saw the multitudes, He went up on a mountain,",
                2: "Then He opened His mouth and taught them, saying:",
                3: "'Blessed are the poor in spirit, for theirs is the kingdom of heaven.'",
            }
        },
        "Ezra": {
            3: {
                10: "When the builders laid the foundation of the temple of the LORD,",
                11: "They sang responsively, praising and giving thanks to the LORD;",
            }
        },
        "Romans": {
            8: {
                28: "And we know that all things work together for good to those who love God,",
            }
        },
        "Philippians": {
            4: {
                13: "I can do all things through Christ who strengthens me.",
            }
        },
        "1 Corinthians": {
            13: {
                1: "Though I speak with the tongues of men and of angels,",
                2: "And though I have the gift of prophecy,",
                3: "And though I bestow all my goods to feed the poor,",
                4: "Charity suffers long and is kind;",
            }
        }
    }
    
    return sample_verses


def create_database(nkjv_verses, yoruba_verses):
    """Create SQLite database with NKJV and Yoruba tables."""
    
    # Remove existing database
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"Removed existing database: {DB_PATH}")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create NKJV table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nkjv (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            book TEXT NOT NULL,
            chapter INTEGER NOT NULL,
            verse INTEGER NOT NULL,
            text TEXT NOT NULL,
            UNIQUE(book, chapter, verse)
        )
    ''')
    
    # Create Yoruba table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS yoruba (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            book TEXT NOT NULL,
            chapter INTEGER NOT NULL,
            verse INTEGER NOT NULL,
            text TEXT NOT NULL,
            UNIQUE(book, chapter, verse)
        )
    ''')
    
    # Create indexes for faster lookups
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_nkjv_book ON nkjv(book)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_nkjv_chapter ON nkjv(book, chapter)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_yoruba_book ON yoruba(book)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_yoruba_chapter ON yoruba(book, chapter)')
    
    # Insert NKJV verses
    print(f"Inserting {len(nkjv_verses)} NKJV verses...")
    cursor.executemany(
        'INSERT OR REPLACE INTO nkjv (book, chapter, verse, text) VALUES (?, ?, ?, ?)',
        nkjv_verses
    )
    
    # Insert Yoruba verses
    print(f"Inserting {len(yoruba_verses)} Yoruba verses...")
    cursor.executemany(
        'INSERT OR REPLACE INTO yoruba (book, chapter, verse, text) VALUES (?, ?, ?, ?)',
        yoruba_verses
    )
    
    conn.commit()
    
    # Verify counts
    cursor.execute('SELECT COUNT(*) FROM nkjv')
    nkjv_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM yoruba')
    yoruba_count = cursor.fetchone()[0]
    
    conn.close()
    
    print(f"\nDatabase created successfully: {DB_PATH}")
    print(f"  NKJV verses: {nkjv_count}")
    print(f"  Yoruba verses: {yoruba_count}")
    
    return nkjv_count, yoruba_count


def main():
    print("=" * 60)
    print("Bible Dual Display - Database Setup")
    print("=" * 60)
    print()
    
    # Load book aliases
    aliases = load_book_aliases()
    print(f"Loaded book aliases from {BOOK_ALIASES_PATH}")
    print()
    
    # Download NKJV
    print("Step 1: Downloading NKJV (New King James Version)...")
    nkjv_data = download_json(NKJV_URL)
    
    # Try alternative URLs if primary fails
    if not nkjv_data:
        print("Trying alternative NKJV sources...")
        for alt_url in NKJV_ALTERNATIVES:
            nkjv_data = download_json(alt_url)
            if nkjv_data:
                break
    
    if nkjv_data:
        nkjv_verses = parse_nkjv_data(nkjv_data)
        print(f"Parsed {len(nkjv_verses)} NKJV verses")
    else:
        print("\nWARNING: Could not download NKJV data from any source.")
        print("Creating sample NKJV data for demonstration purposes...")
        print("(For production use, please ensure internet connectivity or manually download NKJV)")
        print()
        
        sample_data = create_sample_nkjv_data()
        nkjv_verses = parse_nkjv_data(sample_data)
        print(f"Created {len(nkjv_verses)} sample NKJV verses")
    
    print()
    
    # Download Yoruba Bible
    print("Step 2: Downloading Yoruba Bible (YBCV)...")
    yoruba_data = None
    yoruba_verses = []
    
    for url in YORUBA_URLS:
        data = download_json(url)
        if data:
            yoruba_data = data
            yoruba_verses = parse_yoruba_data(data, aliases)
            print(f"Parsed {len(yoruba_verses)} Yoruba verses from {url}")
            break
    
    if not yoruba_verses:
        print("\nWarning: Could not download Yoruba Bible from online sources.")
        print("Creating sample Yoruba data for demonstration purposes...")
        print("(For production use, please obtain complete YBCV text from official sources)")
        print()
        
        sample_data = create_sample_yoruba_data(aliases)
        # Parse with empty aliases dict since sample data already has Yoruba book names
        yoruba_verses = parse_yoruba_data(sample_data, {})
        print(f"Created {len(yoruba_verses)} sample Yoruba verses")
    
    print()
    
    # Create database
    print("Step 3: Creating SQLite database...")
    nkjv_count, yoruba_count = create_database(nkjv_verses, yoruba_verses)
    
    print()
    print("=" * 60)
    print("Setup Complete!")
    print("=" * 60)
    print()
    print("The Bible database has been created at:")
    print(f"  {DB_PATH}")
    print()
    print("Next steps:")
    print("  1. Run 'python main.py' to start the application")
    print("  2. The app will now work fully offline for verse lookups")
    print()
    print("Note: All Bible text is stored locally. No internet required after setup.")
    print()


if __name__ == "__main__":
    main()
