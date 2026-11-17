from sqlalchemy import String, Integer, Double, Index
from sqlalchemy.orm import Mapped, mapped_column
from src.config.database import Base


class KeyRotation(Base):
    """一次密钥轮换的持久化单据。重试沿用同一单据，绝不重复创建。"""
    __tablename__ = 'key_rotations'
    id: Mapped[int] = mapped_column(primary_key=True)
    old_key_id: Mapped[str] = mapped_column(String(40))
    new_key_id: Mapped[str] = mapped_column(String(40), unique=True)
    # running（迁移中）/ completed（全部迁完并已停用旧密钥）
    status: Mapped[str] = mapped_column(String(20), default='running')
    total: Mapped[int] = mapped_column(Integer, default=0)
    migrated: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[float] = mapped_column(Double)
    finished_at: Mapped[float | None] = mapped_column(Double, nullable=True)
    note: Mapped[str] = mapped_column(String(500), default='')


class RotationItem(Base):
    """轮换明细：每个待迁对象一行，中断后据此接着恢复。"""
    __tablename__ = 'rotation_items'
    __table_args__ = (
        Index('idx_rotation_items_rotation', 'rotation_id'),
        Index('idx_rotation_items_unique', 'rotation_id', 'kind', 'ref_id', 'detail', unique=True),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    rotation_id: Mapped[int] = mapped_column(Integer)
    # dataset / job / artifact
    kind: Mapped[str] = mapped_column(String(20))
    ref_id: Mapped[int] = mapped_column(Integer)
    # artifact 类型时区分 csv / json；数据库对象为空
    detail: Mapped[str] = mapped_column(String(20), default='')
    # pending / done / failed
    state: Mapped[str] = mapped_column(String(20), default='pending')
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(String(1000), default='')
    updated_at: Mapped[float] = mapped_column(Double)
