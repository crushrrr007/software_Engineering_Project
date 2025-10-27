"""
Logging utility for MalCapture Defender
Provides comprehensive logging with rotation and colored output
"""

import logging
import colorlog
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime


class MalCaptureLogger:
    """Custom logger for the MalCapture Defender application"""

    def __init__(self, name, log_dir="logs", console_level=logging.INFO, file_level=logging.DEBUG):
        """
        Initialize the logger

        Args:
            name: Logger name
            log_dir: Directory to store log files
            console_level: Logging level for console output
            file_level: Logging level for file output
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        self.log_dir = log_dir

        # Create logs directory if it doesn't exist
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Prevent duplicate handlers
        if self.logger.handlers:
            return

        # Console handler with color
        console_handler = colorlog.StreamHandler()
        console_handler.setLevel(console_level)
        console_format = colorlog.ColoredFormatter(
            '%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            }
        )
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)

        # File handler with rotation
        log_file = os.path.join(log_dir, f"{name}_{datetime.now().strftime('%Y%m%d')}.log")
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(file_level)
        file_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)

    def get_logger(self):
        """Return the configured logger"""
        return self.logger


def get_logger(name, log_dir="logs"):
    """
    Factory function to get a logger instance

    Args:
        name: Logger name
        log_dir: Directory to store log files

    Returns:
        logging.Logger: Configured logger instance
    """
    mal_logger = MalCaptureLogger(name, log_dir)
    return mal_logger.get_logger()
