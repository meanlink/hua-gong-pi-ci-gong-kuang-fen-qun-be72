"""幂等建表与静态加密升级。

- 新部署：直接按加密列建表。
- 旧部署：原 JSON 列改为 LONGTEXT（密文信封是字符串），并补齐密钥 ID 列；
  历史明文保持可读，由轮换迁移流程重新加密，业务无需停机。
"""
from sqlalchemy import inspect, text

from src.config.database import Base, engine
from src.utils.crypto import keyring

_ENCRYPTED_JSON_TABLES = {
    'datasets': ['records'],
    'jobs': ['params', 'result'],
}
_KEY_ID_COLUMNS = {
    'datasets': 'crypto_key_id',
    'jobs': 'crypto_key_id',
    'deliveries': 'crypto_key_id',
}


def _existing_columns(conn, table: str) -> set[str]:
    return {c['name'] for c in inspect(conn).get_columns(table)}


def _upgrade_existing(conn):
    inspector = inspect(conn)
    tables = set(inspector.get_table_names())
    dialect = engine.dialect.name
    for table, columns in _ENCRYPTED_JSON_TABLES.items():
        if table not in tables:
            continue
        present = _existing_columns(conn, table)
        for column in columns:
            if column not in present:
                continue
            col_type = next(c['type'] for c in inspector.get_columns(table) if c['name'] == column)
            if dialect == 'mysql' and str(col_type).upper() != 'LONGTEXT':
                conn.execute(text(f'ALTER TABLE `{table}` MODIFY COLUMN `{column}` LONGTEXT NULL'))
            elif dialect == 'sqlite' and str(col_type).upper() != 'TEXT':
                # SQLite 动态类型对存储透明，JSON 声明同样能写字符串，无需重建表
                pass
    for table, column in _KEY_ID_COLUMNS.items():
        if table in tables and column not in _existing_columns(conn, table):
            nullable = 'NULL' if table == 'deliveries' else "NOT NULL DEFAULT ''"
            conn.execute(text(f'ALTER TABLE `{table}` ADD COLUMN `{column}` VARCHAR(40) {nullable}'))


def migrate():
    keyring.ensure_initialized()
    with engine.begin() as conn:
        _upgrade_existing(conn)
    Base.metadata.create_all(engine)


if __name__ == '__main__':
    migrate()
