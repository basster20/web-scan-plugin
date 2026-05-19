#!/usr/bin/env python3
"""
main.py - Bible Dual Display (NKJV + Yoruba) with NDI Output

Main application coordinator that:
- Provides tkinter GUI for verse display and input
- Integrates voice recognition (push-to-talk F2)
- Sends output to NDI for streaming software
- Manages local Bible database queries
- Logs all actions to bible_dual.log

Usage:
    1. First run: python data/setup_bible.py (to create bible.db)
    2. Then run: python main.py

All Bible text is stored locally. No internet required after initial setup.
"""

import os
import sys
import json
import logging
import threading
from datetime import datetime
from typing import Optional, List, Dict, Any

# Configure logging first
LOG_FILE = 'bible_dual.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Import local modules
from local_bible import get_bible_db, close_bible_db, BibleDatabase
from verse_parser import VerseParser, VerseReference, parse_verse_reference
from ndi_sender import get_ndi_sender, close_ndi_sender, NDIBibleSender
from voice_listener import get_voice_listener, close_voice_listener, VoiceListener

# Try to import tkinter
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False
    logger.error("tkinter not available. GUI will not work.")

# Configuration file path
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')


class Config:
    """Application configuration management."""
    
    DEFAULTS = {
        'ndi_source_name': 'BibleDualDisplay',
        'font_size': 40,
        'hotkey': 'f2',
        'language': 'en-US',
        'ndi_enabled': True,
        'microphone_device': 'default',
        'window_width': 1200,
        'window_height': 800,
    }
    
    def __init__(self, config_path: str = CONFIG_PATH):
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create defaults."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    saved_config = json.load(f)
                    # Merge with defaults
                    return {**self.DEFAULTS, **saved_config}
            except Exception as e:
                logger.warning(f"Error loading config: {e}, using defaults")
        
        return self.DEFAULTS.copy()
    
    def save(self):
        """Save configuration to file."""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
            logger.info("Configuration saved")
        except Exception as e:
            logger.error(f"Error saving config: {e}")
    
    def get(self, key: str, default=None):
        """Get configuration value."""
        return self.config.get(key, default)
    
    def set(self, key: str, value):
        """Set configuration value."""
        self.config[key] = value
    
    @property
    def ndi_source_name(self) -> str:
        return self.config.get('ndi_source_name', self.DEFAULTS['ndi_source_name'])
    
    @property
    def font_size(self) -> int:
        return self.config.get('font_size', self.DEFAULTS['font_size'])
    
    @property
    def hotkey(self) -> str:
        return self.config.get('hotkey', self.DEFAULTS['hotkey'])
    
    @property
    def ndi_enabled(self) -> bool:
        return self.config.get('ndi_enabled', self.DEFAULTS['ndi_enabled'])


class BibleHistoryItem:
    """Represents a verse in the history."""
    
    def __init__(self, verses: List[Dict[str, Any]], timestamp: datetime):
        self.verses = verses
        self.timestamp = timestamp
    
    def get_display_text(self) -> str:
        """Get short display text for history list."""
        if not self.verses:
            return "Empty"
        
        ref = self.verses[0].get('reference', 'Unknown')
        time_str = self.timestamp.strftime('%H:%M:%S')
        return f"[{time_str}] {ref}"


class BibleDualApp:
    """Main application class for Bible Dual Display."""
    
    def __init__(self):
        """Initialize the application."""
        logger.info("Starting Bible Dual Display application")
        
        # Load configuration
        self.config = Config()
        
        # Initialize components
        self.bible_db: Optional[BibleDatabase] = None
        self.ndi_sender: Optional[NDIBibleSender] = None
        self.voice_listener: Optional[VoiceListener] = None
        self.parser = VerseParser()
        
        # Current state
        self.current_verses: List[Dict[str, Any]] = []
        self.history: List[BibleHistoryItem] = []
        self.max_history = 5
        
        # NDI frame update thread
        self._ndi_update_thread: Optional[threading.Thread] = None
        self._stop_ndi_thread = False
        
        # Create GUI
        if not TKINTER_AVAILABLE:
            logger.error("tkinter not available. Cannot create GUI.")
            raise RuntimeError("tkinter not available")
        
        self.root = tk.Tk()
        self.root.title("Bible Dual Display - NKJV & Yoruba")
        self.root.configure(bg='#000000')
        
        # Set window size
        width = self.config.get('window_width', 1200)
        height = self.config.get('window_height', 800)
        self.root.geometry(f"{width}x{height}")
        
        # Build UI
        self._build_ui()
        
        # Initialize backend components
        self._initialize_components()
        
        # Bind events
        self._bind_events()
        
        logger.info("Application initialized successfully")
    
    def _build_ui(self):
        """Build the user interface."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(
            main_frame,
            text="Bible Dual Display",
            font=('Arial', 16, 'bold')
        )
        title_label.grid(row=0, column=0, pady=(0, 10))
        
        # Display area (shows current verse)
        display_frame = ttk.LabelFrame(main_frame, text="Display Preview", padding="10")
        display_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        display_frame.columnconfigure(0, weight=1)
        display_frame.rowconfigure(0, weight=1)
        
        self.display_text = scrolledtext.ScrolledText(
            display_frame,
            wrap=tk.WORD,
            bg='#000000',
            fg='#FFFFFF',
            font=('Arial', self.config.font_size),
            padx=20,
            pady=20
        )
        self.display_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Input area
        input_frame = ttk.LabelFrame(main_frame, text="Verse Input", padding="10")
        input_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=10)
        input_frame.columnconfigure(1, weight=1)
        
        # Text entry
        ttk.Label(input_frame, text="Reference:").grid(row=0, column=0, padx=5)
        self.entry_var = tk.StringVar()
        self.entry = ttk.Entry(input_frame, textvariable=self.entry_var, width=50)
        self.entry.grid(row=0, column=1, padx=5, sticky=(tk.W, tk.E))
        self.entry.bind('<Return>', lambda e: self._on_show_clicked())
        
        # Show button
        self.show_btn = ttk.Button(input_frame, text="Show", command=self._on_show_clicked)
        self.show_btn.grid(row=0, column=2, padx=5)
        
        # Push-to-talk button
        self.ptt_btn = ttk.Button(input_frame, text="🎤 Push-to-Talk (F2)", command=self._toggle_voice)
        self.ptt_btn.grid(row=0, column=3, padx=5)
        
        # History area
        history_frame = ttk.LabelFrame(main_frame, text="History (Last 5)", padding="10")
        history_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=10)
        history_frame.columnconfigure(0, weight=1)
        
        self.history_listbox = tk.Listbox(history_frame, height=5, bg='#1a1a1a', fg='#ffffff')
        self.history_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E))
        self.history_listbox.bind('<<ListboxSelect>>', self._on_history_select)
        
        # Settings area
        settings_frame = ttk.LabelFrame(main_frame, text="Settings", padding="10")
        settings_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=10)
        settings_frame.columnconfigure(1, weight=1)
        
        # NDI toggle
        ttk.Label(settings_frame, text="NDI Output:").grid(row=0, column=0, padx=5)
        self.ndi_var = tk.BooleanVar(value=self.config.ndi_enabled)
        self.ndi_check = ttk.Checkbutton(
            settings_frame,
            variable=self.ndi_var,
            command=self._on_ndi_toggle
        )
        self.ndi_check.grid(row=0, column=1, sticky=tk.W)
        
        # Font size
        ttk.Label(settings_frame, text="Font Size:").grid(row=0, column=2, padx=5)
        self.font_size_var = tk.StringVar(value=str(self.config.font_size))
        self.font_size_combo = ttk.Combobox(
            settings_frame,
            textvariable=self.font_size_var,
            values=['30', '35', '40', '45', '50'],
            width=5
        )
        self.font_size_combo.grid(row=0, column=3, padx=5)
        self.font_size_combo.bind('<<ComboboxSelected>>', self._on_font_size_change)
        
        # NDI source name
        ttk.Label(settings_frame, text="NDI Name:").grid(row=0, column=4, padx=5)
        self.ndi_name_var = tk.StringVar(value=self.config.ndi_source_name)
        self.ndi_name_entry = ttk.Entry(settings_frame, textvariable=self.ndi_name_var, width=20)
        self.ndi_name_entry.grid(row=0, column=5, padx=5)
        self.ndi_name_entry.bind('<Return>', self._on_ndi_name_change)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Database info
        self.db_info_var = tk.StringVar(value="")
        db_info_label = ttk.Label(main_frame, textvariable=self.db_info_var)
        db_info_label.grid(row=6, column=0, sticky=tk.W)
    
    def _initialize_components(self):
        """Initialize backend components."""
        try:
            # Initialize Bible database
            self.bible_db = get_bible_db()
            
            # Check database status
            db_stats = self.bible_db.verify_database()
            if 'error' in db_stats:
                logger.error(f"Database error: {db_stats['error']}")
                self.db_info_var.set("❌ Database error")
                messagebox.showerror(
                    "Database Error",
                    f"Bible database not found or corrupted.\n\n"
                    f"Please run: python data/setup_bible.py\n\n"
                    f"Error: {db_stats['error']}"
                )
            else:
                nkjv_count = db_stats.get('nkjv_verses', 0)
                yoruba_count = db_stats.get('yoruba_verses', 0)
                self.db_info_var.set(f"✓ Database: NKJV={nkjv_count:,} | Yoruba={yoruba_count:,}")
                logger.info(f"Database loaded: NKJV={nkjv_count}, Yoruba={yoruba_count}")
            
            # Initialize NDI sender
            self.ndi_sender = get_ndi_sender(self.config.ndi_source_name)
            
            if self.config.ndi_enabled:
                if self.ndi_sender.start_ndi():
                    self.status_var.set("NDI Streaming")
                    logger.info("NDI streaming started")
                else:
                    self.status_var.set("NDI Not Available")
                    self.ndi_var.set(False)
                    logger.warning("NDI not available")
            else:
                self.status_var.set("Ready (NDI disabled)")
            
            # Initialize voice listener
            self.voice_listener = get_voice_listener(
                hotkey=self.config.hotkey,
                language=self.config.get('language', 'en-US')
            )
            self.voice_listener.set_callback(self._on_voice_input)
            
            # Start voice listener thread
            self.voice_listener.start_listening()
            
            # Update placeholder on NDI
            self._update_ndi_display(show_placeholder=True)
            
        except Exception as e:
            logger.error(f"Error initializing components: {e}")
            messagebox.showwarning("Initialization Warning", f"Some features may not work: {e}")
    
    def _bind_events(self):
        """Bind keyboard and other events."""
        # Global hotkey handling (for when app has focus)
        self.root.bind('<F2>', lambda e: self._trigger_voice())
        
        # Window close handler
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def _on_show_clicked(self):
        """Handle show button click."""
        reference_text = self.entry_var.get().strip()
        if not reference_text:
            return
        
        self._process_reference(reference_text)
    
    def _process_reference(self, text: str):
        """Process a verse reference and display it."""
        logger.info(f"Processing reference: '{text}'")
        
        try:
            # Parse the reference
            parsed_ref = self.parser.parse(text)
            
            if not parsed_ref:
                messagebox.showwarning("Invalid Reference", f"Could not parse: {text}")
                return
            
            # Fetch verses from database
            if parsed_ref.is_chapter_only:
                verses = self.bible_db.get_chapter(parsed_ref.book, parsed_ref.chapter)
            elif parsed_ref.end_verse and parsed_ref.end_verse != parsed_ref.start_verse:
                verses = self.bible_db.get_verse_range(
                    parsed_ref.book,
                    parsed_ref.chapter,
                    parsed_ref.start_verse,
                    parsed_ref.end_verse
                )
            else:
                verse = self.bible_db.get_verse(
                    parsed_ref.book,
                    parsed_ref.chapter,
                    parsed_ref.start_verse
                )
                verses = [verse]
            
            # Check for errors
            if verses and 'error' in verses[0]:
                messagebox.showwarning("Not Found", verses[0]['error'])
                return
            
            # Update display
            self.current_verses = verses
            self._update_display(verses)
            self._update_ndi_display(verses)
            
            # Add to history
            self._add_to_history(verses)
            
            # Clear entry
            self.entry_var.set("")
            
            logger.info(f"Displayed: {parsed_ref}")
            
        except Exception as e:
            logger.error(f"Error processing reference: {e}")
            messagebox.showerror("Error", f"Failed to display verse: {e}")
    
    def _update_display(self, verses: List[Dict[str, Any]]):
        """Update the GUI display with verses."""
        self.display_text.delete(1.0, tk.END)
        
        for verse_data in verses:
            reference = verse_data.get('reference', '')
            nkjv_text = verse_data.get('nkjv', '[Translation missing]')
            yoruba_text = verse_data.get('yoruba', '[Translation missing]')
            
            # Format for display
            display_text = f"{reference}\n"
            display_text += f"NKJV: {nkjv_text}\n"
            display_text += f"Yoruba: {yoruba_text}\n"
            display_text += "\n"
            
            self.display_text.insert(tk.END, display_text)
        
        # Scroll to top
        self.display_text.see(tk.END)
    
    def _update_ndi_display(self, verses: List[Dict[str, Any]] = None,
                           show_placeholder: bool = False):
        """Update the NDI output."""
        if not self.ndi_sender or not self.config.ndi_enabled:
            return
        
        try:
            self.ndi_sender.send_frame(verses, show_placeholder)
        except Exception as e:
            logger.error(f"Error updating NDI: {e}")
    
    def _add_to_history(self, verses: List[Dict[str, Any]]):
        """Add verses to history."""
        item = BibleHistoryItem(verses, datetime.now())
        self.history.insert(0, item)
        
        # Trim history
        while len(self.history) > self.max_history:
            self.history.pop()
        
        # Update listbox
        self.history_listbox.delete(0, tk.END)
        for item in self.history:
            self.history_listbox.insert(tk.END, item.get_display_text())
    
    def _on_history_select(self, event):
        """Handle history item selection."""
        selection = self.history_listbox.curselection()
        if not selection:
            return
        
        index = selection[0]
        if 0 <= index < len(self.history):
            item = self.history[index]
            self.current_verses = item.verses
            self._update_display(item.verses)
            self._update_ndi_display(item.verses)
    
    def _toggle_voice(self):
        """Toggle voice listening mode."""
        if not self.voice_listener:
            messagebox.showinfo("Voice Input", "Voice input is not available.")
            return
        
        status = self.voice_listener.get_status()
        if not status['speech_available'] or not status['keyboard_available']:
            messagebox.showinfo(
                "Voice Input",
                "Voice input requires:\n"
                "- speech_recognition library\n"
                "- keyboard library\n"
                "- microphone\n\n"
                "Install: pip install speechrecognition keyboard pyaudio"
            )
            return
        
        # Simulate hotkey press
        self._trigger_voice()
    
    def _trigger_voice(self):
        """Trigger voice capture (simulate F2 press)."""
        if self.voice_listener and self.voice_listener.recognizer:
            logger.info("Voice capture triggered")
            # The voice listener handles the actual capture in its thread
    
    def _on_voice_input(self, text: str):
        """Handle recognized voice input."""
        logger.info(f"Voice input received: '{text}'")
        
        # Update entry field
        self.entry_var.set(text)
        
        # Auto-process if it looks like a verse reference
        if self.parser.parse(text):
            self._process_reference(text)
    
    def _on_ndi_toggle(self):
        """Handle NDI enable/disable toggle."""
        enabled = self.ndi_var.get()
        
        if enabled:
            if self.ndi_sender and self.ndi_sender.start_ndi():
                self.status_var.set("NDI Streaming")
                self.config.set('ndi_enabled', True)
                logger.info("NDI enabled")
            else:
                self.ndi_var.set(False)
                self.status_var.set("NDI Not Available")
                messagebox.showwarning(
                    "NDI Error",
                    "Could not start NDI output.\n\n"
                    "Make sure:\n"
                    "1. NDI SDK is installed\n"
                    "2. ndi-python package is installed\n"
                    "3. NDI runtime is running"
                )
        else:
            if self.ndi_sender:
                self.ndi_sender.stop_ndi()
            self.status_var.set("Ready (NDI disabled)")
            self.config.set('ndi_enabled', False)
            logger.info("NDI disabled")
    
    def _on_font_size_change(self, event=None):
        """Handle font size change."""
        try:
            size = int(self.font_size_var.get())
            self.config.set('font_size', size)
            
            # Update display font
            self.display_text.config(font=('Arial', size))
            
            logger.info(f"Font size changed to {size}")
        except ValueError:
            pass
    
    def _on_ndi_name_change(self, event=None):
        """Handle NDI source name change."""
        name = self.ndi_name_var.get().strip()
        if name:
            self.config.set('ndi_source_name', name)
            if self.ndi_sender:
                self.ndi_sender.set_source_name(name)
            logger.info(f"NDI source name changed to: {name}")
    
    def _on_close(self):
        """Handle application close."""
        logger.info("Closing application...")
        
        # Save configuration
        self.config.save()
        
        # Stop NDI thread
        self._stop_ndi_thread = True
        
        # Close components
        if self.voice_listener:
            self.voice_listener.stop_listening()
        
        if self.ndi_sender:
            self.ndi_sender.stop_ndi()
        
        close_bible_db()
        close_ndi_sender()
        close_voice_listener()
        
        self.root.destroy()
        logger.info("Application closed")
    
    def run(self):
        """Run the application main loop."""
        logger.info("Starting application main loop")
        self.root.mainloop()


def main():
    """Main entry point."""
    print("=" * 60)
    print("Bible Dual Display - NKJV & Yoruba")
    print("=" * 60)
    print()
    print("This application displays Bible verses in both NKJV and Yoruba.")
    print("All Bible text is stored locally. No internet required after setup.")
    print()
    print("Usage:")
    print("  - Type a verse reference (e.g., 'John 3:16') and press Enter")
    print("  - Press F2 and speak to use voice input")
    print("  - Output is sent to NDI for use in OBS/vMix")
    print()
    print("Log file: bible_dual.log")
    print()
    
    try:
        app = BibleDualApp()
        app.run()
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        print(f"\nFatal error: {e}")
        print("\nTroubleshooting:")
        print("  1. Make sure you've run: python data/setup_bible.py")
        print("  2. Check bible_dual.log for details")
        print("  3. Ensure all dependencies are installed:")
        print("     pip install -r requirements.txt")
        sys.exit(1)


if __name__ == "__main__":
    main()
