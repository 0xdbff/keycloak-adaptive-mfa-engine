"""
# AuthContext Data Model

The **AuthContext** model captures contextual information about an authentication attempt.
This includes client details, IP address, device characteristics, and other metadata.
"""

from sqlalchemy import Column, String, Float, Boolean, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import validates

from .base import Base

from src.core.sql_dialect import hashed_str, text_str
from src.utils.validation.regex import SHA256_REGEX_HEX


class AuthContext(Base):
    """
    ## Fields

    - **hash (String)**:
      Primary key to uniquely identify the auth context record.
    - **device (String)**:
      Identifies the specific device or device name.
    - **client (String)**:
      The client application name or identifier.
    - **ip_address (String)**:
      IP address from which the request originated.
    - **system_language (String)**:
      Language setting on the system.
    - **screen_resolution (String)**:
      Resolution setting of the client device's screen.
    - **operating_system (String)**:
      Operating system name or version.
    - **browser (String)**:
      Browser name or version.
    - **lat (Float)**:
      Latitude component of the user's location.
    - **long (Float)**:
      Longitude component of the user's location.
    - **is_vpn (Boolean)**:
      Indicates if the user is behind a VPN.
    - **country_name (String)**:
      Detected or reported country name of the user.
    - **created_at (DateTime)**:
      Automatic timestamp (with timezone) indicating when the record was created.

    ## Validators

    - **validate_hash**:
      Enforces 64 character hexadecimal string for 'hash' field.
    """

    __tablename__ = "auth_context"

    hash = Column(
        hashed_str(64),
        primary_key=True,
        doc="Primary key to uniquely identify the auth context record.",
    )

    device = Column(text_str(128), doc="Device information.")
    client = Column(
        text_str(128), nullable=False, doc="The client application name or identifier."
    )
    ip_address = Column(
        String(45), nullable=False, doc="IP address from which the request originated."
    )
    system_language = Column(
        text_str(64), nullable=False, doc="Language setting on the system."
    )
    screen_resolution = Column(
        String(64),
        nullable=False,
        doc="Resolution setting of the client device's screen.",
    )
    operating_system = Column(text_str(64), doc="Operating system information.")
    browser = Column(text_str(64), doc="Browser information.")
    lat = Column(Float, doc="Latitude component of the user's location.")
    long = Column(Float, doc="Longitude component of the user's location.")
    is_vpn = Column(Boolean, doc="Indicates if the user is behind a VPN.")
    country_name = Column(
        text_str(32), doc="Detected or reported country name of the user."
    )

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
