import time, os, csv, io, hashlib, json
from fastapi import HTTPException
from src.models import Job, Report, Delivery
from src.config.settings import ARTIFACT_DIR
from src.utils.crypto import keyring, encrypt_bytes, CiphertextInvalidError, KeyMissingError, ENVELOPE_PREFIX


def create(db, data):
    j = db.get(Job, data.job_id)
    if not j or j.status != 'completed' or not j.approved:
        raise HTTPException(409, '请先选择已完成且获批准的分析结果')
    r = Report(name=data.name, job_id=j.id, destination=data.destination,
               interval_seconds=data.interval_seconds, next_run=time.time() + data.delay_seconds, enabled=True)
    db.add(r); db.flush()
    return r


def _artifact_label(suffix: str) -> str:
    # 空后缀对应 CSV 本体，AAD 标签与写入端严格一致
    return 'deliveries.' + (suffix.lstrip('.') or 'csv')


def _write_encrypted(path: str, content: bytes, label: str):
    # 原子写入：先落临时文件再替换，避免留下半份产物
    envelope = encrypt_bytes(content, label)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(envelope)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def deliver(db, report):
    j = db.get(Job, report.job_id)
    if not j or not j.approved:
        return
    out = io.StringIO()
    out.write('﻿')
    table = j.result.get('table', {})
    cols = table.get('columns', [])
    writer = csv.writer(out)
    def safe(v):
        if isinstance(v, (int, float)) and not isinstance(v, bool): return v
        text = str(v)
        return "'" + text if text.startswith(('=', '+', '-', '@', '\t', '\r')) else text
    writer.writerow([safe(c['label']) for c in cols])
    for row in table.get('rows', []):
        writer.writerow([safe(row.get(c['key'], '')) for c in cols])
    data = out.getvalue().encode('utf-8')
    snapshot = json.dumps({'job': j.name, 'params': j.params, 'result': j.result,
                           'checksum': hashlib.sha256(data).hexdigest()},
                          ensure_ascii=False, allow_nan=False).encode('utf-8')
    delivery = Delivery(report_id=report.id, created_at=time.time(),
                        checksum=hashlib.sha256(data).hexdigest(), filename='',
                        destination=report.destination, crypto_key_id=keyring.current_key_id())
    db.add(delivery); db.flush()
    delivery.filename = f'report-{report.id}-delivery-{delivery.id}.csv'
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    # 简报产物静态加密后落盘，密钥不随产物保存
    _write_encrypted(os.path.join(ARTIFACT_DIR, delivery.filename), data, _artifact_label(''))
    _write_encrypted(os.path.join(ARTIFACT_DIR, delivery.filename + '.json'), snapshot, _artifact_label('.json'))
    report.next_run = time.time() + report.interval_seconds
    return delivery


def read_artifact(filename: str, suffix: str) -> bytes:
    """读取产物并解密；密文损坏或密钥缺失时显式拒绝，不返回半份结果。"""
    path = os.path.join(ARTIFACT_DIR, filename + suffix)
    if not os.path.exists(path):
        raise HTTPException(404, '归档文件不存在，请重新安排分发')
    with open(path, 'rb') as f:
        raw = f.read()
    if not raw.startswith(ENVELOPE_PREFIX.encode('ascii')):
        # 历史明文产物：直接返回，由轮换流程逐步加密
        return raw
    try:
        return keyring.decrypt(raw.decode('utf-8'), _artifact_label(suffix))
    except CiphertextInvalidError as exc:
        raise HTTPException(422, str(exc)) from exc
    except KeyMissingError as exc:
        raise HTTPException(503, str(exc) + '；请联系管理员恢复密钥环') from exc
