# Bible Dual Display - NKJV & Yoruba with NDI Output

A desktop application that displays Bible verses simultaneously in **NKJV** (New King James Version) and **Yoruba Bible (YBCV)** with NDI® video output for streaming software.

![Application Preview](preview.png)

## Features

- **Dual-Language Display**: Shows Bible verses in both English (NKJV) and Yoruba (YBCV) simultaneously
- **NDI Output**: 1920×1080 video source compatible with OBS Studio, vMix, Wirecast, and other NDI-enabled software
- **Voice Input**: Push-to-talk (F2 hotkey) for hands-free verse selection
- **Offline Operation**: All Bible text stored locally after initial setup
- **Book Name Aliases**: Supports both English and Yoruba book names (e.g., "Ezra" or "Esra")
- **Verse Ranges**: Display single verses, verse ranges, or entire chapters
- **History**: Quick access to last 5 displayed verses
- **Customizable**: Font size, NDI source name, and more

## Requirements

### System Requirements
- Python 3.9 or higher
- Windows, macOS, or Linux
- Microphone (for voice input)
- NDI Runtime (for NDI output)

### Software Dependencies

#### NDI SDK Installation

**Windows:**
1. Download NDI SDK from [https://www.ndi.tv/sdk/](https://www.ndi.tv/sdk/)
2. Install the NDI Runtime
3. Install Python wrapper: `pip install ndi-python`

**macOS:**
1. Download NDI SDK for macOS
2. Install via Homebrew: `brew install ndi-sdk` (if available)
3. Or manually install from NewTek website
4. Install Python wrapper: `pip install ndi-python`

**Linux:**
1. Download NDI SDK for Linux from NewTek
2. Extract and install following the included instructions
3. Install Python wrapper: `pip install ndi-python`

Note: The `ndi-python` package requires the NDI SDK to be installed first. If NDI is not available, the application will still work but without NDI output.

## Installation

### Step 1: Clone or Download

```bash
cd bible_dual_ndi
```

### Step 2: Install Python Dependencies

```bash
pip install -r requirements.txt
```

The requirements include:
- `Pillow` - Image processing for NDI frames
- `speechrecognition` - Voice recognition
- `PyAudio` - Microphone access
- `keyboard` - Hotkey handling
- `ndi-python` - NDI output (optional)

### Step 3: Set Up Bible Database

Run the setup script to download and create the local Bible database:

```bash
python data/setup_bible.py
```

This will:
1. Download NKJV from scrollmapper GitHub repository
2. Attempt to download Yoruba Bible (YBCV) from available sources
3. Create `bible.db` SQLite database with both translations
4. Generate sample Yoruba verses if full YBCV is unavailable

**Important**: This step requires internet connection. After completion, the app works fully offline.

### Step 4: Run the Application

```bash
python main.py
```

## Usage

### Text Input

1. Type a verse reference in the input field (e.g., "John 3:16")
2. Press Enter or click "Show"
3. The verse appears in both languages on screen and in NDI output

### Voice Input

1. Press and hold **F2** (push-to-talk)
2. Speak the verse reference clearly (e.g., "John chapter 3 verse 16")
3. Release F2
4. The recognized text is processed automatically

**Example voice commands:**
- "John 3:16"
- "Psalm 23"
- "Ezra 3:10 to 12"
- "First Corinthians 13"
- "Johanu 3:16" (Yoruba book name)

### Supported Reference Formats

| Format | Example | Description |
|--------|---------|-------------|
| Single verse | `John 3:16` | One specific verse |
| Chapter only | `Psalm 23` | Entire chapter |
| Verse range | `Ezra 3:10-12` | Multiple consecutive verses |
| With number | `1 Corinthians 13` | Books with numbers |
| Yoruba names | `Saamu 23` | Using Yoruba book names |

### Book Name Examples

| English | Yoruba |
|---------|--------|
| Genesis | Genesisi |
| Exodus | Eksodu |
| Psalms | Saamu |
| John | Johanu |
| Matthew | Matteu |
| Romans | Romu |
| Ephesians | Efesu |

See `data/book_aliases.json` for complete list.

### NDI Output

When enabled, the application sends a continuous 1920×1080 video stream named "BibleDualDisplay" (configurable).

**To use in OBS Studio:**
1. Start the Bible Dual Display application
2. Ensure NDI output is enabled (checkbox in settings)
3. In OBS: Add → Source → NDI Source
4. Select "BibleDualDisplay" from the list

**To use in vMix:**
1. Start the application
2. In vMix: Add Input → NDI
3. Select "BibleDualDisplay"

### Settings

- **NDI Output**: Toggle NDI streaming on/off
- **Font Size**: Adjust text size (30-50pt)
- **NDI Name**: Change the NDI source name

## Project Structure

```
bible_dual_ndi/
├── main.py                 # Main application (GUI + coordinator)
├── local_bible.py          # Database queries for NKJV & Yoruba
├── verse_parser.py         # Parse verse references from text/voice
├── ndi_sender.py           # NDI video output generation
├── voice_listener.py       # Voice recognition with push-to-talk
├── data/
│   ├── setup_bible.py      # Database setup script
│   └── book_aliases.json   # English ↔ Yoruba book name mappings
├── bible.db                # SQLite database (created by setup)
├── config.json             # User preferences (auto-created)
├── bible_dual.log          # Application log file
├── requirements.txt        # Python dependencies
└── README.md               # This file
```

## Troubleshooting

### NDI Not Detected

**Symptoms**: Status shows "NDI Not Available" or checkbox won't stay enabled

**Solutions:**
1. Verify NDI Runtime is installed:
   - Windows: Check Programs & Features for "NDI Runtime"
   - Run `ndiinfo.exe` (Windows) to test NDI installation
2. Reinstall ndi-python:
   ```bash
   pip uninstall ndi-python
   pip install ndi-python
   ```
3. Restart your computer after NDI SDK installation
4. Try disabling and re-enabling NDI in the app settings

### Missing Yoruba Text

**Symptoms**: Shows "[Translation missing]" for Yoruba verses

**Solutions:**
1. Re-run the setup script:
   ```bash
   python data/setup_bible.py
   ```
2. Check if Yoruba Bible source URLs are accessible
3. The setup creates sample Yoruba verses for common passages. For complete YBCV:
   - Obtain full Yoruba Bible text from official sources
   - Convert to JSON format matching the NKJV structure
   - Place in `data/ybcv.json` and re-run setup

### Microphone Permissions

**Symptoms**: Voice input doesn't work, no audio captured

**Solutions:**

**Windows:**
1. Settings → Privacy → Microphone
2. Enable "Allow apps to access your microphone"
3. Ensure Python has microphone permission

**macOS:**
1. System Preferences → Security & Privacy → Privacy → Microphone
2. Check Python or Terminal in the list
3. Restart the application

**Linux:**
1. Check microphone permissions: `ls -la /dev/snd/*`
2. Add user to audio group: `sudo usermod -a -G audio $USER`
3. Log out and back in

### Voice Recognition Not Working

**Symptoms**: Pressing F2 does nothing or fails to recognize speech

**Solutions:**
1. Verify required packages:
   ```bash
   pip install speechrecognition keyboard pyaudio
   ```
2. Test microphone separately (e.g., with system sound recorder)
3. Speak clearly and wait for the full phrase before releasing F2
4. Note: Google Speech Recognition requires internet connection

### Database Errors

**Symptoms**: "Database error" message on startup

**Solutions:**
1. Delete corrupted database and recreate:
   ```bash
   rm bible.db
   python data/setup_bible.py
   ```
2. Check `bible_dual.log` for detailed error messages
3. Ensure write permissions in the application directory

## Logging

All application activity is logged to `bible_dual.log`. Include this file when reporting issues.

Log entries include:
- Database queries
- Verse references processed
- NDI status changes
- Voice recognition events
- Errors and warnings

## Offline Operation

**After initial setup, the application works completely offline:**

- ✅ Bible text: Stored locally in SQLite database
- ✅ Book name lookups: Local JSON file
- ✅ GUI display: No network required
- ❌ Voice recognition: Uses Google API (requires internet)
  - Alternative: Use text input only, or install offline speech recognition (Vosk)
- ❌ Initial setup: Requires internet to download Bible data

For fully offline operation including voice recognition, consider integrating Vosk offline speech recognition library.

## License

- NKJV text: Used under appropriate license (public domain / fair use for display)
- Yoruba Bible: Check specific translation license
- Application code: MIT License (see LICENSE file)

## Contributing

Contributions welcome! Areas for improvement:
- Additional Bible translations
- Improved Yoruba Bible coverage
- Offline speech recognition integration
- Better word-wrapping algorithms
- Theme customization

## Support

For issues or questions:
1. Check `bible_dual.log` for error details
2. Review this README's troubleshooting section
3. Verify all dependencies are installed correctly

---

**Note**: NDI® is a registered trademark of Vizrt North America Inc. This application uses NDI technology but is not affiliated with or endorsed by Vizrt.
