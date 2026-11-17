"""密钥轮换与分批迁移。

并发正确性要点：
1. rotate() 先在密钥环切换当前密钥，之后所有新写入立即使用新密钥；
2. 迁移逐行加行锁（with_for_update），并以列内密文信封的实际密钥 ID
   作为判据；在途写入若抢先以新密钥提交，迁移识别后跳过，绝不会用旧
   密钥内容覆盖它（防止旧密钥内容被重新落盘）；
3. 内容相等时 ORM 不标脏，迁移用 flag_modified 强制重加密，杜绝只改
   密钥标记而载荷仍是旧信封的“假迁移”；
4. 只有全部存量与在途对象迁移完成、复核无旧密钥/明文残留后才停用旧密钥；
5. 单据与明细持久化在数据库，worker 中断后从 pending/failed 项接着跑，
   重复发起轮换返回同一单据，不新增轮换、不丢失记录。
"""
import os
import time
import logging

from sqlalchemy import select, update, func, text
from sqlalchemy.orm.attributes import flag_modified

from src.config.database import Session
from src.config.settings import ARTIFACT_DIR, ROTATION_BATCH_SIZE
from src.models import Dataset, Job, Delivery, KeyRotation, RotationItem, Audit
from src.services.audit import record
from src.utils.crypto import keyring, encrypt_bytes, CiphertextInvalidError, KeyMissingError, ENVELOPE_PREFIX

logger = logging.getLogger(__name__)


def _artifact_label(suffix: str) -> str:
    # 与 services.reports 的 AAD 标签严格一致：空后缀对应 CSV 本体
    return 'deliveries.' + (suffix.lstrip('.') or 'csv')


def _artifact_path(filename: str, suffix: str) -> str:
    return os.path.join(ARTIFACT_DIR, filename + suffix)


def _open_artifact(delivery: Delivery, suffix: str):
    """读取产物：兼容历史明文与加密信封，返回 (字节内容, 是否加密)。"""
    path = _artifact_path(delivery.filename, suffix)
    if not os.path.exists(path):
        raise FileNotFoundError(f'产物文件缺失：{os.path.basename(path)}')
    with open(path, 'rb') as f:
        raw = f.read()
    if raw.startswith(ENVELOPE_PREFIX.encode('ascii')):
        return keyring.decrypt(raw.decode('utf-8'), _artifact_label(suffix)), True
    # 历史明文文件：原样迁移
    return raw, False


def _write_artifact_encrypted(path: str, content: bytes, suffix: str):
    envelope = encrypt_bytes(content, _artifact_label(suffix))
    tmp = path + '.migrating'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(envelope)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def start_rotation(db) -> KeyRotation:
    """发起轮换；已有进行中的轮换时直接返回它，保证不重复创建。"""
    existing = db.scalar(select(KeyRotation).where(KeyRotation.status == 'running').order_by(KeyRotation.id.desc()))
    if existing:
        return existing
    old_key_id, new_key_id = keyring.rotate()
    rotation = KeyRotation(
        old_key_id=old_key_id, new_key_id=new_key_id, status='running',
        started_at=time.time(),
    )
    db.add(rotation)
    db.flush()
    _enqueue_existing(db, rotation)
    return rotation


def _new_key_prefix(key_id: str) -> str:
    return ENVELOPE_PREFIX + key_id + '::'


def _enqueue_existing(db, rotation: KeyRotation):
    """枚举仍由旧密钥保护（或历史明文、或密钥标记与载荷不一致）的对象。

    判据同时看冗余密钥 ID 列与列内密文信封的实际密钥 ID：即使在途写入
    只推进了密钥标记，载荷仍是旧信封的对象也必须进入迁移明细。
    """
    now = time.time()
    prefix = _new_key_prefix(rotation.new_key_id)
    for d_id, in db.execute(select(Dataset.id).where(
            ~Dataset.records.like(prefix + '%'))):
        db.add(RotationItem(rotation_id=rotation.id, kind='dataset', ref_id=d_id, updated_at=now))
    for j_id, in db.execute(select(Job.id).where(
            ~Job.params.like(prefix + '%') | ~Job.result.like(prefix + '%'))):
        db.add(RotationItem(rotation_id=rotation.id, kind='job', ref_id=j_id, updated_at=now))
    # 产物以交付记录的密钥标记为准（文件在最终复核中逐份校验）
    for delivery_id, in db.execute(select(Delivery.id).where(
            (Delivery.crypto_key_id == rotation.old_key_id)
            | (Delivery.crypto_key_id != rotation.new_key_id)
            | (Delivery.crypto_key_id.is_(None)))):
        for suffix in ('', '.json'):
            db.add(RotationItem(rotation_id=rotation.id, kind='artifact', ref_id=delivery_id,
                                detail=suffix.lstrip('.'), updated_at=now))
    db.flush()
    rotation.total = db.scalar(
        select(func.count()).select_from(RotationItem).where(RotationItem.rotation_id == rotation.id)) or 0


def _mark_item(db, item: RotationItem, state: str, error: str = ''):
    item.state = state
    item.attempts += 1
    item.last_error = error[:990]
    item.updated_at = time.time()


def _already_new(value, new_key_id: str) -> bool:
    """以载荷信封中的实际密钥 ID 为准，避免只看冗余标记而漏掉旧信封。"""
    return isinstance(value, str) and value.startswith(_new_key_prefix(new_key_id))


def _process_dataset(db, item: RotationItem, rotation: KeyRotation):
    dataset = db.get(Dataset, item.ref_id, with_for_update=True)
    if dataset is None:
        _mark_item(db, item, 'done', '对象已删除')
        return
    if _already_new(db.execute(text('SELECT records FROM datasets WHERE id=:i'),
                               {'i': dataset.id}).scalar(), rotation.new_key_id):
        # 在途写入已抢先完成重加密
        dataset.crypto_key_id = rotation.new_key_id
        _mark_item(db, item, 'done')
        return
    # 强制重绑：先解密（兼容明文），再以当前密钥重新加密落盘。
    # 内容相等时 SQLAlchemy 不会自动标脏，必须显式 flag_modified，
    # 否则只会更新密钥 ID 而密文仍是旧信封（绝不允许的假迁移）。
    records = dataset.records
    dataset.records = records
    flag_modified(dataset, 'records')
    dataset.crypto_key_id = rotation.new_key_id
    _mark_item(db, item, 'done')


def _process_job(db, item: RotationItem, rotation: KeyRotation):
    job = db.get(Job, item.ref_id, with_for_update=True)
    if job is None:
        _mark_item(db, item, 'done', '对象已删除')
        return
    row = db.execute(text('SELECT params, result FROM jobs WHERE id=:i'), {'i': job.id}).one()
    if _already_new(row.params, rotation.new_key_id) and _already_new(row.result, rotation.new_key_id):
        job.crypto_key_id = rotation.new_key_id
        _mark_item(db, item, 'done')
        return
    params, result = job.params, job.result
    job.params = params
    job.result = result
    flag_modified(job, 'params')
    flag_modified(job, 'result')
    job.crypto_key_id = rotation.new_key_id
    _mark_item(db, item, 'done')


def _process_artifact(db, item: RotationItem, rotation: KeyRotation):
    delivery = db.get(Delivery, item.ref_id, with_for_update=True)
    if delivery is None:
        _mark_item(db, item, 'done', '对象已删除')
        return
    suffix = '.' + item.detail if item.detail else ''
    path = _artifact_path(delivery.filename, suffix)
    if delivery.crypto_key_id == rotation.new_key_id and os.path.exists(path):
        with open(path, 'rb') as f:
            if f.read(16).startswith(ENVELOPE_PREFIX.encode('ascii')):
                _mark_item(db, item, 'done')
                return
    content, _was_encrypted = _open_artifact(delivery, suffix)
    _write_artifact_encrypted(path, content, suffix)
    _mark_item(db, item, 'done')
    # 两个文件（CSV/JSON）都迁完才更新交付记录的密钥 ID
    remaining = db.scalar(select(func.count()).select_from(RotationItem).where(
        RotationItem.rotation_id == rotation.id, RotationItem.kind == 'artifact',
        RotationItem.ref_id == delivery.id, RotationItem.state != 'done'))
    if not remaining:
        delivery.crypto_key_id = rotation.new_key_id


_PROCESSORS = {'dataset': _process_dataset, 'job': _process_job, 'artifact': _process_artifact}


def process_batch(db, rotation: KeyRotation) -> int:
    """处理一批明细，返回本批成功数。任何单项失败都不影响其他对象。"""
    items = list(db.scalars(
        select(RotationItem).where(
            RotationItem.rotation_id == rotation.id,
            RotationItem.state.in_(('pending', 'failed')))
        .order_by(RotationItem.id).limit(ROTATION_BATCH_SIZE)))
    succeeded = 0
    for item in items:
        try:
            _PROCESSORS[item.kind](db, item, rotation)
            succeeded += 1
        except (CiphertextInvalidError, KeyMissingError, FileNotFoundError, OSError, ValueError) as exc:
            logger.warning('轮换明细 %s 迁移失败：%s', item.id, exc)
            _mark_item(db, item, 'failed', str(exc))
        except Exception as exc:  # 防御：单对象异常不能拖垮整个轮换
            logger.exception('轮换明细发生未预期错误')
            _mark_item(db, item, 'failed', f'未预期错误：{exc}')
    db.flush()
    _refresh_counters(db, rotation)
    return succeeded


def _refresh_counters(db, rotation: KeyRotation):
    base = select(func.count()).select_from(RotationItem).where(RotationItem.rotation_id == rotation.id)
    rotation.total = db.scalar(base) or 0
    rotation.migrated = db.scalar(base.where(RotationItem.state == 'done')) or 0
    rotation.failed = db.scalar(base.where(RotationItem.state == 'failed')) or 0


def _no_legacy_left(db, rotation: KeyRotation) -> tuple[bool, str]:
    """最终复核：数据库行与产物文件都不得残留旧密钥或明文。"""
    prefix = ENVELOPE_PREFIX + rotation.new_key_id + '::'
    # 直接核对列中密文信封的实际密钥 ID，而不仅是冗余的密钥 ID 列
    for table, columns in (('datasets', ('records',)), ('jobs', ('params', 'result'))):
        for column in columns:
            total = db.execute(text(f'SELECT COUNT(*) FROM "{table}"')).scalar()
            good = db.execute(
                text(f'SELECT COUNT(*) FROM "{table}" WHERE "{column}" LIKE :p'),
                {'p': prefix + '%'}).scalar()
            if good != total:
                return False, f'表 {table}.{column} 仍有 {total - good} 行未以新密钥加密（含明文或旧信封）'
    stale_deliveries = db.scalar(select(func.count()).select_from(Delivery).where(
        (Delivery.crypto_key_id != rotation.new_key_id) | (Delivery.crypto_key_id.is_(None))))
    if stale_deliveries:
        return False, f'仍有 {stale_deliveries} 份简报产物未使用新密钥'
    # 逐文件检查信封与密钥 ID
    for delivery in db.scalars(select(Delivery)):
        for suffix in ('', '.json'):
            path = _artifact_path(delivery.filename, suffix)
            if not os.path.exists(path):
                return False, f'产物文件缺失：{os.path.basename(path)}'
            with open(path, 'r', encoding='utf-8') as f:
                envelope = f.read()
            if not envelope.startswith(ENVELOPE_PREFIX):
                return False, f'产物仍为明文：{os.path.basename(path)}'
            if keyring.envelope_key_id(envelope) != rotation.new_key_id:
                return False, f'产物仍引用旧密钥：{os.path.basename(path)}'
    return True, ''


def finalize_if_ready(db, rotation: KeyRotation) -> bool:
    _refresh_counters(db, rotation)
    if rotation.failed or rotation.total != rotation.migrated:
        return False
    ok, reason = _no_legacy_left(db, rotation)
    if not ok:
        rotation.note = reason
        return False
    # 全部存量与在途内容迁完，才停用旧密钥（材料保留，仅应急解密）
    keyring.retire(rotation.old_key_id)
    rotation.status = 'completed'
    rotation.finished_at = time.time()
    rotation.note = '所有对象已迁移至新密钥，旧密钥已停用（保留材料仅用于应急）'
    record(db, 'worker', 'key.rotation.completed',
           {'id': rotation.id, 'old_key_id': rotation.old_key_id, 'new_key_id': rotation.new_key_id,
            'total': rotation.total})
    return True


def retry_failed(db, rotation: KeyRotation) -> int:
    """把失败对象重新排队，沿用同一轮换单据，不新增轮换。"""
    count = db.scalar(select(func.count()).select_from(RotationItem).where(
        RotationItem.rotation_id == rotation.id, RotationItem.state == 'failed')) or 0
    db.execute(update(RotationItem).where(
        RotationItem.rotation_id == rotation.id, RotationItem.state == 'failed'
    ).values(state='pending', updated_at=time.time()))
    _refresh_counters(db, rotation)
    return count


def run_pending_rotations():
    """worker 每个 tick 调用：驱动进行中的轮换，直到完成或等待失败重试。"""
    with Session() as db:
        rotation = db.scalar(select(KeyRotation).where(KeyRotation.status == 'running').order_by(KeyRotation.id.desc()))
        if not rotation:
            return
        process_batch(db, rotation)
        finalize_if_ready(db, rotation)
        db.commit()


def rotation_summary(db, rotation: KeyRotation) -> dict:
    _refresh_counters(db, rotation)
    return {
        'id': rotation.id,
        'old_key_id': rotation.old_key_id,
        'new_key_id': rotation.new_key_id,
        'status': rotation.status,
        'total': rotation.total,
        'migrated': rotation.migrated,
        'failed': rotation.failed,
        'pending': rotation.total - rotation.migrated - rotation.failed,
        'started_at': rotation.started_at,
        'finished_at': rotation.finished_at,
        'note': rotation.note,
    }


def list_rotations(db, limit: int = 20) -> list[dict]:
    rows = db.scalars(select(KeyRotation).order_by(KeyRotation.id.desc()).limit(limit))
    return [rotation_summary(db, r) for r in rows]


def list_failures(db, rotation_id: int, limit: int = 100) -> list[dict]:
    rows = db.scalars(select(RotationItem).where(
        RotationItem.rotation_id == rotation_id, RotationItem.state == 'failed'
    ).order_by(RotationItem.id).limit(limit))
    return [{'id': i.id, 'kind': i.kind, 'ref_id': i.ref_id, 'detail': i.detail,
             'attempts': i.attempts, 'last_error': i.last_error, 'updated_at': i.updated_at} for i in rows]
