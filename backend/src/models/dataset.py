from sqlalchemy import String, Double
from sqlalchemy.orm import Mapped, mapped_column
from src.config.database import Base
from src.utils.crypto_types import EncryptedJSON
from src.utils.crypto import current_key_id


class Dataset(Base):
    __tablename__ = 'datasets'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True)
    source: Mapped[str] = mapped_column(String(200), default='manual.json')
    # 原始工况静态加密落盘；AAD 绑定 datasets.records
    records: Mapped[list] = mapped_column(EncryptedJSON('datasets.records'))
    checksum: Mapped[str] = mapped_column(String(64))
    # 冗余密钥 ID：迁移时做 SQL 级守卫，避免在途写入把旧密钥内容重新落盘
    crypto_key_id: Mapped[str] = mapped_column(String(40), default=current_key_id)
    created_at: Mapped[float] = mapped_column(Double)
