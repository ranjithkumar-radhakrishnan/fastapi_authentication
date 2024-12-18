import uuid

from sqlalchemy import Column, Integer, String, ForeignKey, Table, Boolean, DateTime
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime, timedelta

from app.api.core.config import AUTH_METHOD

Base = declarative_base()

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    roles = relationship("Role", secondary=user_roles, back_populates="users")

    if AUTH_METHOD == 'API_KEY':
        api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)

    users = relationship("User", secondary=user_roles, back_populates="roles")


if AUTH_METHOD == 'API_KEY':
    class APIKey(Base):
        __tablename__ = "api_keys"

        id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        key = Column(String, unique=True, nullable=False, index=True)
        user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
        revoked = Column(Boolean, default=False)
        expiry_date = Column(DateTime, nullable=False,
                             default=lambda: datetime.utcnow() + timedelta(days=30))
        user = relationship("User", back_populates="api_keys")
