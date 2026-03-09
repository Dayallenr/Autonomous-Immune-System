import logging
import os
from config.settings import settings


def setup_logging(name: str = "immune_system") -> logging.Logger:
    os.makedirs(os.path.dirname(settings.log_file), exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))

    if not logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(name)s] %(levelname)s %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        logger.addHandler(console_handler)

        file_handler = logging.FileHandler(settings.log_file)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(name)s] %(levelname)s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(file_handler)

    return logger
