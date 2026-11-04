"""
# Device Model

The **Device** model holds information about a specific device used
during authentication.
"""

from sqlalchemy import Column, String, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import validates

from .base import Base

from src.core.sql_dialect import hashed_str, text_str
from src.utils.validation.regex import SHA256_REGEX_HEX


class Device(Base):
    """
    ## Fields

    - **hash (String)**:
      Primary key to uniquely identify the device record.
    - **client (String)**:
      Name or identifier of the client application on the device.
    - **system_language (String)**:
      Language setting on the device.
    - **screen_resolution (String)**:
      Resolution setting of the device's display.
    - **operating_system (String)**:
      Name of the device's operating system.
    - **browser (String)**:
      Name or version of the device's browser.
    - **created_at (DateTime)**:
      Timestamp (with timezone) noting when the record was created.

    ## Validators

    - **validate_hash**:
      Enforces 64 character hexadecimal string for 'hash' field.
    """

    __tablename__ = "device"

    hash = Column(
        hashed_str(64),
        primary_key=True,
        doc="Primary key to uniquely identify the device record.",
    )
    client = Column(
        text_str(128),
        doc="Optional descriptive information about the device.",
    )
    device = Column(
        text_str(64),
        nullable=False,
        doc="Name or identifier of the client application on the device.",
    )
    system_language = Column(
        text_str(64), nullable=False, doc="System language setting on the device."
    )
    screen_resolution = Column(
        String(64), nullable=False, doc="Screen resolution setting on the device."
    )
    operating_system = Column(text_str(64), doc="Operating system name on the device.")
    browser = Column(text_str(64), doc="Browser name or version on the device.")

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="Auto Timestamp noting when the record was created.",
    )

    @validates("hash")
    def validate_hash(self, key, value):
        """
        Ensures that the `hash` field is a valid 64-character hex string (SHA-256).
        Raises a ValueError if the hash is invalid.
        """
        if not SHA256_REGEX_HEX.match(value):
            raise ValueError(
                f"Invalid hash value: '{value}'. Must be a 64-character hex string."
            )
        return value
