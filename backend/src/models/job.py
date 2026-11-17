from sqlalchemy import String, Double, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from src.config.database import Base
from src.utils.crypto_types import EncryptedJSON
from src.utils.crypto import current_key_id


class Job(Base):
    __tablename__ = 'jobs'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    dataset_id: Mapped[int] = mapped_column(ForeignKey('datasets.id'))
    # 分析参数与结果均静态加密，AAD 分别绑定 jobs.params / jobs.result
    params: Mapped[dict] = mapped_column(EncryptedJSON('jobs.params'), default=dict)
    status: Mapped[str] = mapped_column(String(20), default='queued')
    result: Mapped[dict] = mapped_column(EncryptedJSON('jobs.result'), default=dict)
    error: Mapped[str] = mapped_column(String(1000), default='')
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[int] = mapped_column(ForeignKey('users.id'))
    crypto_key_id: Mapped[str] = mapped_column(String(40), default=current_key_id)
    created_at: Mapped[float] = mapped_column(Double)
    finished_at: Mapped[float | None] = mapped_column(Double, nullable=True)
