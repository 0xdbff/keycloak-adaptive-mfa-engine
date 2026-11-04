"""
# AuthProcess Data Model

The **AuthProcess** data model represents an individual authentication
transaction for a particular user. It is the complete process of a login or
attempt, references various tables:

- authentication context
- device info
- network location info combined
- parameters configuration
- authentication events


**Indexes**
To facilitate faster retrieval of the most recent records, a composite index
is defined over `(user_id, final_status, finished_at DESC)`. This ordering
prioritizes queries that filter on `user_id` and `final_status` while also
sorting by the latest finish time first.
"""

import uuid

from sqlalchemy import (
    Column,
    String,
    Float,
    Integer,
    DateTime,
    ForeignKey,
    JSON,
    Index,
    Uuid,
    desc,
)
from sqlalchemy.sql import func
from sqlalchemy.orm import validates

from src.core.sql_dialect import hashed_str, ident_str, uuid_server_default

from .base import Base


class AuthProcess(Base):
    """
    ## Fields

    - **id (UUID)**:
      Primary key for the AuthProcess; defaults to a generated UUID (v4).
    - **user_id (UUID)**:
      The user initiating this authentication process.
    - **auth_context_hash (String)**:
      Reference to the associated `auth_context` table using its `hash`.
    - **device_info_hash (String)**:
      Reference to the associated `device` table using its `hash`.
    - **network_location_hash (String)**:
      Reference to the associated `location_network` table using its `hash`.
    - **auth_context_json (JSON)**:
      All JSON data with the authentication context.
    - **pre_auth_risk_decision (Integer)**:
      Integer representing a pre-authentication risk evaluation.
    - **parameters_config_id (UUID)**:
      Foreign key reference to the `decision_params_config` table,
      indicating the parameters config used for the risk evaluation.
    - **final_status (String)**:
      Describes the final authentication status.
    - **started_at (DateTime)**:
      Timestamp (with timezone) denoting when the process started.
    - **finished_at (DateTime)**:
      Timestamp (with timezone) denoting when the process ended.
    """

    __tablename__ = "auth_process"
    __table_args__ = (
        Index(
            "ix_auth_process_realm_user_final_finished",
            "realm_id",
            "user_id",
            "final_status",
            desc("finished_at"),
        ),
    )

    id = Column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=uuid_server_default(),
        doc="Primary key: auto-generated UUID (v4).",
    )
    user_id = Column(
        Uuid(as_uuid=True),
        nullable=False,
        doc="References the user initiating this auth process.",
    )
    realm_id = Column(
        ident_str(255),
        nullable=True,
        doc=(
            "The Keycloak realm (tenant) this record belongs to, taken from the "
            "authenticated caller's token realm, never from client-supplied input. "
            "Every per-user read/write must filter on this so one tenant's token "
            "cannot reach another tenant's authentication history."
        ),
    )
    auth_context_hash = Column(
        hashed_str(64),
        nullable=False,
        doc="Auth_context hash.",
    )
    device_info_hash = Column(
        hashed_str(64),
        ForeignKey("device.hash"),
        nullable=False,
        doc="References the device.hash.",
    )
    device_credibility = Column(Float, nullable=True, default=0.0)
    network_location_hash = Column(
        hashed_str(64),
        ForeignKey("location_network.hash"),
        nullable=False,
        doc="References the location_network.hash.",
    )
    net_loc_credibility = Column(Float, nullable=True, default=0.0)

    auth_context_json = Column(
        JSON,
        nullable=False,
        doc="JSON data of the pre-authentication information, with additional internal calculations.",
    )
    risk_eval_vars = Column(
        JSON,
        nullable=True,
    )
    pre_auth_risk_decision = Column(
        Integer, nullable=False, doc="Numerical indicator for pre-auth risk analysis."
    )
    parameters_config_id = Column(
        Uuid(as_uuid=True),
        ForeignKey("decision_params_config.id"),
        nullable=False,
        doc="References the associated parameters config.",
    )
    final_status = Column(
        String(32),
        nullable=False,
        doc="Final status of the authentication process.",
    )

    started_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="Auto Timestamp noting when the process started.",
    )
    finished_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        doc="Auto Timestamp noting when the process concluded.",
    )

    @validates("id", "user_id")
    def validate_uuid(self, key, value):
        if isinstance(value, uuid.UUID):
            return value
        try:
            return uuid.UUID(str(value))
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError(f"Invalid UUID v4 {value}.") from exc
