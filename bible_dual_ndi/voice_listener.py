#!/usr/bin/env python3
"""
voice_listener.py - Voice recognition for Bible verse input.

Features:
- Push-to-talk with configurable hotkey (default F2)
- Speech-to-text using speech_recognition library
- Graceful fallback when microphone unavailable
- Thread-based listening to avoid blocking GUI
"""

import os
import sys
import logging
import threading
from typing import Optional, Callable, Dict, Any
from datetime import datetime

# Try to import speech recognition libraries
try:
    import speech_recognition as sr
    SPEECH_AVAILABLE = True
except ImportError:
    SPEECH_AVAILABLE = False
    logging.warning("speech_recognition not available. Voice input disabled.")

try:
    import keyboard
    KEYBOARD_AVAILABLE = True
except ImportError:
    KEYBOARD_AVAILABLE = False
    logging.warning("keyboard library not available. Hotkey support disabled.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class VoiceListener:
    """Handle voice input for Bible verse references."""
    
    def __init__(self, hotkey: str = 'f2', language: str = 'en-US'):
        """
        Initialize voice listener.
        
        Args:
            hotkey: Hotkey for push-to-talk (e.g., 'f2')
            language: Speech recognition language code
        """
        self.hotkey = hotkey
        self.language = language
        self.is_listening = False
        self.is_hotkey_active = False
        self.callback: Optional[Callable[[str], None]] = None
        self._listener_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Initialize speech recognizer
        if SPEECH_AVAILABLE:
            self.recognizer = sr.Recognizer()
            self.microphone: Optional[sr.Microphone] = None
            self._setup_microphone()
        else:
            self.recognizer = None
            self.microphone = None
        
        logger.info(f"VoiceListener initialized (Hotkey: {hotkey}, Language: {language})")
        logger.info(f"Speech recognition available: {SPEECH_AVAILABLE}")
        logger.info(f"Keyboard hooks available: {KEYBOARD_AVAILABLE}")
    
    def _setup_microphone(self):
        """Set up the microphone for speech recognition."""
        if not SPEECH_AVAILABLE:
            return
        
        try:
            # List available microphones
            available_mics = sr.Microphone.list_microphone_names()
            logger.info(f"Available microphones: {available_mics}")
            
            # Try to use default microphone
            self.microphone = sr.Microphone()
            
            # Adjust for ambient noise
            with self.microphone as source:
                logger.info("Adjusting for ambient noise...")
                self.recognizer.adjust_for_ambient_noise(source, duration=1)
                logger.info("Ambient noise adjustment complete")
                
        except Exception as e:
            logger.error(f"Error setting up microphone: {e}")
            self.microphone = None
    
    def set_callback(self, callback: Callable[[str], None]):
        """
        Set callback function to be called when speech is recognized.
        
        Args:
            callback: Function that takes recognized text as argument
        """
        self.callback = callback
        logger.info("Callback function registered")
    
    def start_listening(self):
        """Start the voice listener thread."""
        if not SPEECH_AVAILABLE or not KEYBOARD_AVAILABLE:
            logger.warning("Voice input not fully available")
            return
        
        if self._listener_thread and self._listener_thread.is_alive():
            logger.warning("Listener thread already running")
            return
        
        self._stop_event.clear()
        self._listener_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._listener_thread.start()
        logger.info("Voice listener thread started")
    
    def stop_listening(self):
        """Stop the voice listener thread."""
        self._stop_event.set()
        
        if self._listener_thread:
            self._listener_thread.join(timeout=2)
            self._listener_thread = None
        
        logger.info("Voice listener thread stopped")
    
    def _listen_loop(self):
        """Main listening loop (runs in separate thread)."""
        logger.info("Listening loop started")
        
        # Register hotkey handler
        if KEYBOARD_AVAILABLE:
            try:
                keyboard.on_press_key(self.hotkey, self._on_hotkey_press)
                keyboard.on_release_key(self.hotkey, self._on_hotkey_release)
                logger.info(f"Hotkey '{self.hotkey}' registered")
            except Exception as e:
                logger.error(f"Failed to register hotkey: {e}")
        
        while not self._stop_event.is_set():
            if self.is_hotkey_active and not self.is_listening:
                # Start listening when hotkey is pressed
                self._start_voice_capture()
            elif not self.is_hotkey_active and self.is_listening:
                # Stop listening when hotkey is released
                self.is_listening = False
            
            self._stop_event.wait(0.1)  # Small delay to prevent CPU hogging
        
        # Unregister hotkeys
        if KEYBOARD_AVAILABLE:
            try:
                keyboard.unhook_all()
            except Exception:
                pass
        
        logger.info("Listening loop ended")
    
    def _on_hotkey_press(self, event):
        """Handle hotkey press event."""
        if event.name == self.hotkey:
            self.is_hotkey_active = True
            logger.debug("Hotkey pressed")
    
    def _on_hotkey_release(self, event):
        """Handle hotkey release event."""
        if event.name == self.hotkey:
            self.is_hotkey_active = False
            logger.debug("Hotkey released")
    
    def _start_voice_capture(self):
        """Capture and recognize speech."""
        if not self.microphone or not self.recognizer:
            return
        
        self.is_listening = True
        logger.info("Listening for speech...")
        
        try:
            with self.microphone as source:
                # Listen for speech (with timeout)
                audio = self.recognizer.listen(source, timeout=5, phrase_time_limit=10)
            
            logger.info("Speech captured, recognizing...")
            
            # Recognize speech using Google Speech Recognition
            # This requires internet connection
            # For offline recognition, consider using Vosk or Sphinx
            try:
                text = self.recognizer.recognize_google(audio, language=self.language)
                logger.info(f"Recognized: '{text}'")
                
                if self.callback:
                    self.callback(text)
                    
            except sr.UnknownValueError:
                logger.warning("Could not understand audio")
            except sr.RequestError as e:
                logger.error(f"Speech recognition service error: {e}")
                
        except sr.WaitTimeoutError:
            logger.warning("No speech detected within timeout")
        except Exception as e:
            logger.error(f"Error during voice capture: {e}")
        finally:
            self.is_listening = False
    
    def get_status(self) -> Dict[str, Any]:
        """Get current voice listener status."""
        return {
            'is_listening': self.is_listening,
            'is_hotkey_active': self.is_hotkey_active,
            'hotkey': self.hotkey,
            'language': self.language,
            'speech_available': SPEECH_AVAILABLE,
            'keyboard_available': KEYBOARD_AVAILABLE,
            'microphone_available': self.microphone is not None
        }
    
    def test_microphone(self) -> bool:
        """Test if microphone is working."""
        if not self.microphone:
            return False
        
        try:
            with self.microphone as source:
                audio = self.recognizer.listen(source, timeout=2)
            return True
        except Exception as e:
            logger.warning(f"Microphone test failed: {e}")
            return False


# Singleton instance
_voice_listener: Optional[VoiceListener] = None


def get_voice_listener(hotkey: str = 'f2', language: str = 'en-US') -> VoiceListener:
    """Get or create the voice listener singleton."""
    global _voice_listener
    if _voice_listener is None:
        _voice_listener = VoiceListener(hotkey, language)
    return _voice_listener


def close_voice_listener():
    """Close the voice listener."""
    global _voice_listener
    if _voice_listener:
        _voice_listener.stop_listening()
        _voice_listener = None


if __name__ == "__main__":
    # Test the voice listener
    print("Testing Voice Listener")
    print("=" * 50)
    
    def on_speech(text):
        print(f"🎤 Recognized: '{text}'")
    
    listener = get_voice_listener('f2')
    listener.set_callback(on_speech)
    
    # Get status
    status = listener.get_status()
    print(f"\nStatus:")
    for key, value in status.items():
        print(f"  {key}: {value}")
    
    print("\nPress F2 and speak to test voice recognition")
    print("Press Ctrl+C to exit")
    
    try:
        listener.start_listening()
        
        # Keep running
        while True:
            import time
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        listener.stop_listening()
        close_voice_listener()
        print("Test complete.")
