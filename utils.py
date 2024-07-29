from datetime import datetime

"""

Meower Utils Module
This module provides logging, error traceback, and other miscellaneous utilities.

This file should never rely on other Meower modules to prevent circular imports.
"""


def log(event: str):
    """
    Print out a log with the current date & time to the Python console.
    """

    timestamp = datetime.now().strftime("%m/%d/%Y %H:%M.%S")

    print("{0}: {1}".format(timestamp, event))
