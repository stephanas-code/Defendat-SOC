import logging
import sys

from pythonjsonlogger import jsonlogger


def setup_logging(level: str) -> None:
    logger = logging.getLogger()
    logger.handlers.clear()
    logger.setLevel(level.upper())

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level.upper())

    formatter = jsonlogger.JsonFormatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    handler.setFormatter(formatter)

    logger.addHandler(handler)
