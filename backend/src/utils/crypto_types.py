"""SQLAlchemy 透明加密列类型。

业务模型继续以 Python 字典/列表读写字段，落盘时由该类型加密为信封
字符串（TEXT/LONGTEXT），加载时解密还原。历史明文 JSON 保持可读，并在
下次写入时自动重新加密，实现无停机迁移。
"""
import json

from sqlalchemy import Text
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy.types import TypeDecorator

from src.utils.crypto import keyring, CiphertextInvalidError, ENVELOPE_PREFIX


class EncryptedJSON(TypeDecorator):
    impl = Text
    cache_ok = False

    def __init__(self, label: str, **kwargs):
        super().__init__(**kwargs)
        # AAD 标签：绑定具体表字段，密文不能跨字段挪用
        self.label = label

    def load_dialect_impl(self, dialect):
        if dialect.name == 'mysql':
            # 密文信封比原 JSON 长，MySQL 用 LONGTEXT 容纳
            return dialect.type_descriptor(LONGTEXT())
        return dialect.type_descriptor(Text())

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        payload = json.dumps(value, ensure_ascii=False, allow_nan=False)
        return keyring.encrypt(payload.encode('utf-8'), self.label)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, (bytes, bytearray)):
            value = value.decode('utf-8')
        if value.startswith(ENVELOPE_PREFIX):
            return json.loads(keyring.decrypt(value, self.label).decode('utf-8'))
        # 历史明文数据：保持可读，由迁移流程或下次写入重新加密
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise CiphertextInvalidError(f'{self.label} 既不是合法密文也不是历史明文，已拒绝读取') from exc
