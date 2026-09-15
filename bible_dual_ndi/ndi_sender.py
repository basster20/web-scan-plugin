#!/usr/bin/env python3
"""
ndi_sender.py - Send Bible verse displays as NDI video source.

This module:
- Creates 1920x1080 images with black background and white text
- Renders dual-language Bible verses (NKJV + Yoruba)
- Sends frames via NDI for use in OBS, vMix, etc.
- Handles fallback when NDI is not available
"""

import os
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont

# Try to import NDI library
try:
    import ndi
    NDI_AVAILABLE = True
except ImportError:
    NDI_AVAILABLE = False
    logging.warning("NDI library not available. NDI output will be disabled.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NDIBibleSender:
    """Send Bible verse displays as NDI video source."""
    
    # Display settings
    WIDTH = 1920
    HEIGHT = 1080
    BG_COLOR = (0, 0, 0)  # Black background
    TEXT_COLOR = (255, 255, 255)  # White text
    REF_COLOR = (200, 200, 200)  # Light grey for reference line
    
    # Font sizes (will be adjusted if fonts not found)
    REF_FONT_SIZE = 48
    VERSE_FONT_SIZE = 40
    
    # Margins
    MARGIN_X = 100
    MARGIN_Y = 80
    LINE_SPACING = 20
    
    def __init__(self, source_name: str = "BibleDualDisplay"):
        """
        Initialize NDI sender.
        
        Args:
            source_name: Name for the NDI source
        """
        self.source_name = source_name
        self.ndi_instance: Optional[Any] = None
        self.is_streaming = False
        
        # Try to load fonts
        self.ref_font = self._load_font(self.REF_FONT_SIZE)
        self.verse_font = self._load_font(self.VERSE_FONT_SIZE)
        
        # Current frame
        self.current_image: Optional[Image.Image] = None
        
        logger.info(f"NDIBibleSender initialized (Source: {source_name})")
        logger.info(f"NDI available: {NDI_AVAILABLE}")
    
    def _load_font(self, size: int) -> ImageFont.FreeTypeFont:
        """Load a font, falling back to default if necessary."""
        # Try common font paths
        font_paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            "/usr/share/fonts/TTF/DejaVuSans.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
            "C:\\Windows\\Fonts\\arial.ttf",
            "arial.ttf",
            "DejaVuSans.ttf",
        ]
        
        for font_path in font_paths:
            try:
                if os.path.exists(font_path):
                    return ImageFont.truetype(font_path, size)
            except Exception:
                continue
        
        # Fall back to default font
        logger.warning(f"Could not load font, using default (size={size})")
        try:
            return ImageFont.truetype("DejaVuSans.ttf", size)
        except Exception:
            return ImageFont.load_default()
    
    def start_ndi(self) -> bool:
        """
        Start NDI streaming.
        
        Returns:
            True if successful, False otherwise
        """
        if not NDI_AVAILABLE:
            logger.error("NDI library not available")
            return False
        
        try:
            # Create NDI sender instance
            # Note: Actual NDI API may vary depending on the Python NDI wrapper
            self.ndi_instance = ndi.SendCreate()
            
            if self.ndi_instance:
                # Configure NDI source
                ndi_params = {
                    'ndi_name': self.source_name,
                }
                
                # Set up the sender
                self.ndi_instance.set_metadata(ndi_params)
                
                self.is_streaming = True
                logger.info(f"NDI streaming started: {self.source_name}")
                return True
            else:
                logger.error("Failed to create NDI sender instance")
                return False
                
        except Exception as e:
            logger.error(f"Error starting NDI: {e}")
            return False
    
    def stop_ndi(self):
        """Stop NDI streaming."""
        if self.ndi_instance:
            try:
                self.ndi_instance.destroy()
            except Exception as e:
                logger.warning(f"Error stopping NDI: {e}")
            
            self.ndi_instance = None
            self.is_streaming = False
            logger.info("NDI streaming stopped")
    
    def create_frame(self, verses: List[Dict[str, Any]], 
                     show_placeholder: bool = False) -> Image.Image:
        """
        Create a 1920x1080 image with Bible verses.
        
        Args:
            verses: List of verse dictionaries with keys:
                   'reference', 'nkjv', 'yoruba'
            show_placeholder: If True, show "Waiting for verse..." message
            
        Returns:
            PIL Image object
        """
        # Create black background
        img = Image.new('RGB', (self.WIDTH, self.HEIGHT), self.BG_COLOR)
        draw = ImageDraw.Draw(img)
        
        if show_placeholder or not verses:
            # Show placeholder message
            placeholder = "Waiting for verse...\n\nPress F2 and speak a verse reference\nor type in the text box."
            
            # Calculate text position (centered)
            bbox = draw.multiline_textbbox(
                (0, 0), 
                placeholder, 
                font=self.verse_font,
                align='center'
            )
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
            
            x = (self.WIDTH - text_width) // 2
            y = (self.HEIGHT - text_height) // 2
            
            draw.multiline_text(
                (x, y),
                placeholder,
                font=self.verse_font,
                fill=self.TEXT_COLOR,
                align='center',
                spacing=self.LINE_SPACING
            )
            
            self.current_image = img
            return img
        
        # Draw verses
        current_y = self.MARGIN_Y
        
        for verse_data in verses:
            if current_y > self.HEIGHT - self.MARGIN_Y:
                # No more space on this frame
                break
            
            reference = verse_data.get('reference', '')
            nkjv_text = verse_data.get('nkjv', '[Translation missing]')
            yoruba_text = verse_data.get('yoruba', '[Translation missing]')
            
            # Draw reference line
            ref_text = reference
            draw.text(
                (self.MARGIN_X, current_y),
                ref_text,
                font=self.ref_font,
                fill=self.REF_COLOR
            )
            current_y += self.REF_FONT_SIZE + self.LINE_SPACING
            
            # Draw NKJV text with word wrapping
            nkjv_lines = self._wrap_text(draw, nkjv_text, self.verse_font, 
                                         self.WIDTH - 2 * self.MARGIN_X)
            for line in nkjv_lines:
                if current_y > self.HEIGHT - self.MARGIN_Y:
                    break
                draw.text((self.MARGIN_X, current_y), line, 
                         font=self.verse_font, fill=self.TEXT_COLOR)
                current_y += self.VERSE_FONT_SIZE + 5
            
            # Add spacing between translations
            current_y += 10
            
            # Draw Yoruba text with word wrapping
            yoruba_lines = self._wrap_text(draw, yoruba_text, self.verse_font,
                                          self.WIDTH - 2 * self.MARGIN_X)
            for line in yoruba_lines:
                if current_y > self.HEIGHT - self.MARGIN_Y:
                    break
                draw.text((self.MARGIN_X, current_y), line,
                         font=self.verse_font, fill=self.TEXT_COLOR)
                current_y += self.VERSE_FONT_SIZE + 5
            
            # Add blank line between verse pairs
            current_y += self.LINE_SPACING * 2
        
        self.current_image = img
        return img
    
    def _wrap_text(self, draw: ImageDraw.Draw, text: str, 
                   font: ImageFont.FreeTypeFont, max_width: int) -> List[str]:
        """
        Wrap text to fit within max_width.
        
        Args:
            draw: ImageDraw object
            text: Text to wrap
            font: Font to use
            max_width: Maximum width in pixels
            
        Returns:
            List of wrapped lines
        """
        words = text.split()
        lines = []
        current_line = ""
        
        for word in words:
            test_line = f"{current_line} {word}".strip()
            bbox = draw.textbbox((0, 0), test_line, font=font)
            text_width = bbox[2] - bbox[0]
            
            if text_width <= max_width:
                current_line = test_line
            else:
                if current_line:
                    lines.append(current_line)
                current_line = word
        
        if current_line:
            lines.append(current_line)
        
        return lines
    
    def send_frame(self, verses: List[Dict[str, Any]] = None,
                   show_placeholder: bool = False) -> bool:
        """
        Create and send a frame via NDI.
        
        Args:
            verses: List of verse dictionaries
            show_placeholder: If True, show placeholder message
            
        Returns:
            True if successful, False otherwise
        """
        # Create the frame
        img = self.create_frame(verses, show_placeholder)
        
        if not self.is_streaming or not self.ndi_instance:
            # Not streaming via NDI, but still generate the image
            return True
        
        try:
            # Convert PIL image to format suitable for NDI
            # NDI typically expects RGBA or specific video formats
            if img.mode != 'RGBA':
                img = img.convert('RGBA')
            
            # Get image data
            width, height = img.size
            image_data = img.tobytes()
            
            # Send via NDI
            # Note: Actual API depends on the NDI Python wrapper being used
            # This is a generic example - adjust based on your NDI library
            
            if hasattr(self.ndi_instance, 'send_video'):
                # Common pattern for NDI wrappers
                self.ndi_instance.send_video(
                    width=width,
                    height=height,
                    color_format=ndi.FOURCC_VIDEO_TYPE_BGRA,  # or appropriate format
                    data=image_data,
                    frame_rate_n=30,
                    frame_rate_d=1
                )
            elif hasattr(self.ndi_instance, 'send'):
                # Alternative API
                self.ndi_instance.send({
                    'width': width,
                    'height': height,
                    'data': image_data
                })
            else:
                logger.warning("Unknown NDI API - cannot send frame")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending NDI frame: {e}")
            return False
    
    def save_frame(self, filename: str, verses: List[Dict[str, Any]] = None,
                   show_placeholder: bool = False) -> bool:
        """
        Save a frame to a file (useful for testing or screenshots).
        
        Args:
            filename: Output filename
            verses: List of verse dictionaries
            show_placeholder: If True, show placeholder message
            
        Returns:
            True if successful, False otherwise
        """
        try:
            img = self.create_frame(verses, show_placeholder)
            img.save(filename)
            logger.info(f"Frame saved to {filename}")
            return True
        except Exception as e:
            logger.error(f"Error saving frame: {e}")
            return False
    
    def set_source_name(self, name: str):
        """Update the NDI source name."""
        self.source_name = name
        logger.info(f"NDI source name updated to: {name}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current NDI status."""
        return {
            'is_streaming': self.is_streaming,
            'source_name': self.source_name,
            'ndi_available': NDI_AVAILABLE,
            'resolution': f"{self.WIDTH}x{self.HEIGHT}"
        }


# Singleton instance
_ndi_sender: Optional[NDIBibleSender] = None


def get_ndi_sender(source_name: str = "BibleDualDisplay") -> NDIBibleSender:
    """Get or create the NDI sender singleton."""
    global _ndi_sender
    if _ndi_sender is None:
        _ndi_sender = NDIBibleSender(source_name)
    return _ndi_sender


def close_ndi_sender():
    """Close the NDI sender connection."""
    global _ndi_sender
    if _ndi_sender:
        _ndi_sender.stop_ndi()
        _ndi_sender = None


if __name__ == "__main__":
    # Test the NDI sender
    print("Testing NDI Bible Sender")
    print("=" * 50)
    
    sender = get_ndi_sender("TestBibleDisplay")
    
    # Test frame creation
    test_verses = [
        {
            'reference': 'John • Johanu 3:16',
            'nkjv': 'For God so loved the world that He gave His only begotten Son, that whoever believes in Him should not perish but have everlasting life.',
            'yoruba': 'Nitori Ọlọrun fẹran agbaye bẹẹ, ti o fi Ọmọ rẹ ọkan ṣoṣo fun wọn, ki ẹnikẹni ti o ba gbagbọ ninu rẹ ma se parun, ṣugbọn ki o ni igbesi aye ainipẹkun.'
        },
        {
            'reference': 'Psalm • Saamu 23:1',
            'nkjv': 'The LORD is my shepherd; I shall not want.',
            'yoruba': 'Oluwa ni oluṣọ-agutan mi; emi ko ni aini.'
        }
    ]
    
    # Create and save a test frame
    sender.save_frame('test_frame.png', test_verses)
    print("Test frame saved to test_frame.png")
    
    # Test placeholder
    sender.save_frame('test_placeholder.png', show_placeholder=True)
    print("Placeholder frame saved to test_placeholder.png")
    
    # Get status
    status = sender.get_status()
    print(f"\nStatus: {status}")
    
    close_ndi_sender()
    print("\nTest complete.")
