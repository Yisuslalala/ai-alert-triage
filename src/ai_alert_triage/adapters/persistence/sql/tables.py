from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AlertRow(Base):
    __tablename__ = "alerts"

    id: Mapped[UUID] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    raw_payload: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql")
    )


class TriageResultRow(Base):
    __tablename__ = "triage_results"
    __table_args__ = (Index("ix_triage_results_severity_triaged_at", "severity", "triaged_at"),)

    alert_id: Mapped[UUID] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    # Plain string instead of a native Postgres enum: adding a severity later
    # then needs no ALTER TYPE migration. The domain enum validates on read.
    severity: Mapped[str] = mapped_column(String(16))
    summary: Mapped[str] = mapped_column(Text)
    model: Mapped[str] = mapped_column(String(200))
    triaged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
