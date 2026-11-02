"""
DecisionParamsConfig Data Model

The **DecisionParamsConfig** model holds configuration parameters used for
pre-authentication risk decision.
"""

import uuid

from sqlalchemy import Column, Boolean, JSON, DateTime, Uuid
from sqlalchemy.sql import func
from sqlalchemy.orm import validates

from src.core.sql_dialect import (
    boolean_false_server_default,
    hashed_str,
    ident_str,
    uuid_server_default,
)

from .base import Base

from src.utils.validation.regex import SHA256_REGEX_HEX


class DecisionParamsConfig(Base):
    """
    ## Fields

    - **id (UUID)**:
      Primary key for the configuration; auto-generated via UUID (v4).
    - **realm_id (String)**:
      Identifier for a specific realm context.
    - **group_id (String)**:
      Identifier for a group or category within the realm.
    - **is_active (Boolean)**:
      Indicates if the configuration is currently active.
    - **parameters (JSON)**:
      Holds the JSON configuration for all parameters and weights associated.
    - **parameters_hash (String)**:
      Parameters hash to identify versions.
    - **created_at (DateTime)**:
      Timestamp (with timezone) noting when the configuration was created.
    - **updated_at (DateTime)**:
      Timestamp (with timezone) noting when the configuration was last updated.

    ## Validators

    - **validate_hash**:
      Enforces 64 character hexadecimal string for 'parameters_hash' field.
    """

    __tablename__ = "decision_params_config"

    id = Column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=uuid_server_default(),
        doc="Primary key: auto-generated UUID (v4).",
    )
    realm_id = Column(
        ident_str(255), nullable=False, doc="Identifier for a specific realm context."
    )
    group_id = Column(
        ident_str(255),
        nullable=False,
        doc="Identifier for a group or category within the realm.",
    )
    is_active = Column(
        Boolean,
        server_default=boolean_false_server_default(),
        default=False,
        doc="Indicates if the configuration is currently active.",
    )
    parameters = Column(JSON, doc="JSON object storing parameter details or rules.")
    parameters_hash = Column(
        hashed_str(64), nullable=False, doc="Parameters JSON hash to identify versions"
    )
    scoring_config = Column(
        JSON,
        nullable=True,
        doc=(
            "Optional per-realm/group risk-scoring configuration "
            "(mode, bias, thresholds). Null falls back to deployment env defaults."
        ),
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="Auto Timestamp noting when the configuration was created.",
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        doc="Auto Timestamp noting when the configuration was last updated.",
    )

    @validates("parameters_hash")
    def validate_hash(self, key, value):
        """
        Ensures that the `parameters_hash` field is a valid 64-character hex
        string (SHA3-256). Raises a ValueError if the hash is missing or invalid.
        """
        if value is None or not SHA256_REGEX_HEX.match(value):
            raise ValueError(
                f"Invalid parameters_hash: {value!r}. Must be a 64-character hex string."
            )
        return value
