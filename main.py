#!/usr/bin/env python3
"""
Recon 9 — Entry Point
Run with:  python main.py
"""

import sys
import os

# Ensure the app directory is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Suppress InsecureRequestWarning for HTTPS without cert verification
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QPalette, QColor, QFont, QIcon
from PyQt6.QtCore import Qt


# Path to assets
ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
ICON_PATH = os.path.join(ASSETS_DIR, "9-removebg-preview-removebg-preview-Picsart-AiImageEnhancer.png")
CLICK_SOUND_PATH = os.path.join(ASSETS_DIR, "click.mp3")


def _apply_palette(app: QApplication) -> None:
    """Set a cohesive dark-mode palette on top of Fusion style."""
    app.setStyle("Fusion")
    pal = QPalette()

    BG     = QColor(13,  17,  23)   # #0d1117
    BG2    = QColor(22,  27,  34)   # #161b22
    BG3    = QColor(33,  38,  45)   # #21262d
    FG     = QColor(201, 209, 217)  # #c9d1d9
    FG_DIM = QColor(139, 148, 158)  # #8b949e
    FG_OFF = QColor(72,  79,  88)   # #484f58
    ACCENT = QColor(88,  166, 255)  # #58a6ff

    pal.setColor(QPalette.ColorRole.Window,           BG)
    pal.setColor(QPalette.ColorRole.WindowText,       FG)
    pal.setColor(QPalette.ColorRole.Base,             BG2)
    pal.setColor(QPalette.ColorRole.AlternateBase,    BG3)
    pal.setColor(QPalette.ColorRole.ToolTipBase,      BG3)
    pal.setColor(QPalette.ColorRole.ToolTipText,      FG)
    pal.setColor(QPalette.ColorRole.Text,             FG)
    pal.setColor(QPalette.ColorRole.BrightText,       QColor(248, 81, 73))
    pal.setColor(QPalette.ColorRole.Button,           BG3)
    pal.setColor(QPalette.ColorRole.ButtonText,       FG)
    pal.setColor(QPalette.ColorRole.Link,             ACCENT)
    pal.setColor(QPalette.ColorRole.Highlight,        ACCENT)
    pal.setColor(QPalette.ColorRole.HighlightedText,  BG)
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, FG_OFF)
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text,       FG_OFF)
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, FG_OFF)

    app.setPalette(pal)


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("Recon 9")
    app.setApplicationVersion("9.0.0")
    app.setOrganizationName("Recon Tools")

    # Set application icon
    if os.path.exists(ICON_PATH):
        app.setWindowIcon(QIcon(ICON_PATH))

    _apply_palette(app)

    # Default monospace/UI font
    font = QFont("Segoe UI", 10)
    font.setStyleHint(QFont.StyleHint.SansSerif)
    app.setFont(font)

    from main_window import MainWindow
    win = MainWindow()
    win.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
