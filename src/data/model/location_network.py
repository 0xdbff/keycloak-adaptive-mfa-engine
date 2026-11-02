"""
LocationNetwork Data Model

The **LocationNetwork** model holds information about the network from which
an authentication request is made. It can capture geolocation labels, IP address,
and whether or not a VPN was detected.
"""

from sqlalchemy import Column, Integer, DateTime, String
from sqlalchemy.sql import func
from sqlalchemy.orm import validates

from .base import Base

from src.core.sql_dialect import hashed_str, text_str
from src.utils.validation.regex import SHA256_REGEX_HEX


class LocationNetwork(Base):
    """
    ## Fields

    - **hash (String)**:
      Primary key to uniquely identify the network record.
    - **geolocation_cluster_label (Integer)**:
      Numeric label for geolocation grouping.
    - **country (Integer)**:
      Numeric code for country.
    - **ip (Integer)**:
      Numeric representation of IP address (e.g., integer form of IPv4).
    - **is_vpn_flag (Integer)**:
      Flag (commonly 0/1) to indicate whether a VPN is detected.
    - **created_at (DateTime)**:
      Automatic timestamp (with timezone) indicating when the record was created.

    ## Validators

    - **validate_hash**:
      Enforces 64 character hexadecimal string for 'hash' field.
    """

    __tablename__ = "location_network"

    hash = Column(
        hashed_str(64),
        primary_key=True,
        doc="Primary key to uniquely identify the network record.",
    )
    geolocation_cluster_label = Column(
        Integer, doc="Numeric label for geolocation grouping."
    )
    country = Column(text_str(32), doc="Numeric code for the country.")
    ip_address = Column(
        String(45), nullable=False, doc="IP address from which the request originated."
    )
    is_vpn_flag = Column(Integer, doc="Indicator of whether a VPN is detected (0/1).")

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="Timestamp noting when the record was created.",
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
