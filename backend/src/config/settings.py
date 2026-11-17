import os
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./local.db')
REDIS_URL = os.getenv('REDIS_URL', 'redis://redis:6379/0')
JWT_SECRET = os.environ.get('JWT_SECRET', 'local-development-change-before-deploy')
ARTIFACT_DIR = os.getenv('ARTIFACT_DIR', '/artifacts')
# 密钥环目录：必须是与业务数据库、产物卷分离的独立挂载，密钥材料不随业务数据保存
KEYRING_DIR = os.getenv('KEYRING_DIR', '/keyring')
# 每次轮换每批处理的对象数量
ROTATION_BATCH_SIZE = int(os.getenv('ROTATION_BATCH_SIZE', '20'))
