from sqlalchemy import Column, Integer, String, Text, UniqueConstraint, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

engine = create_engine("sqlite:///threatlens.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("type", "value", name="uq_type_value"),)

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String(10), nullable=False)
    value = Column(String(255), nullable=False, index=True)
    source = Column(String(50))
    first_seen = Column(String(10))
    times_seen = Column(Integer, default=1)
    malware_family = Column(String(50))
    # filled in by later steps
    score = Column(Integer, nullable=True)
    severity = Column(String(10), nullable=True)
    tags = Column(String(200), default="")
    score_breakdown = Column(Text, nullable=True)
    status = Column(String(15), default="Pending")
    analyst_note = Column(Text, default="")

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "source": self.source,
            "first_seen": self.first_seen,
            "times_seen": self.times_seen,
            "malware_family": self.malware_family,
            "score": self.score,
            "severity": self.severity,
            "tags": self.tags.split(",") if self.tags else [],
            "status": self.status,
            "analyst_note": self.analyst_note,
        }
