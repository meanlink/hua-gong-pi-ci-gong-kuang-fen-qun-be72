from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from src.config.database import get_db
from src.models import KeyRotation
from src.middlewares.auth import current_user, admin_only
from src.services import rotation
from src.services.audit import record
from src.utils.crypto import keyring, KeyUseError

router = APIRouter(prefix='/key-rotation')


@router.get('/status')
def status(db=Depends(get_db), u=Depends(current_user)):
    """密钥环状态（仅 ID，不含密钥材料）与最近轮换。"""
    return {'keyring': keyring.status(), 'rotations': rotation.list_rotations(db)}


@router.post('/start', status_code=201)
def start(db=Depends(get_db), u=Depends(admin_only)):
    try:
        r = rotation.start_rotation(db)
        record(db, u.email, 'key.rotation.start',
               {'id': r.id, 'old_key_id': r.old_key_id, 'new_key_id': r.new_key_id})
        db.commit()
        return rotation.rotation_summary(db, r)
    except KeyUseError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get('/{rotation_id}')
def detail(rotation_id: int, db=Depends(get_db), u=Depends(current_user)):
    r = db.get(KeyRotation, rotation_id)
    if not r:
        raise HTTPException(404, '轮换单据不存在')
    return rotation.rotation_summary(db, r)


@router.get('/{rotation_id}/failures')
def failures(rotation_id: int, db=Depends(get_db), u=Depends(current_user)):
    if not db.get(KeyRotation, rotation_id):
        raise HTTPException(404, '轮换单据不存在')
    return {'items': rotation.list_failures(db, rotation_id)}


@router.post('/{rotation_id}/retry')
def retry(rotation_id: int, db=Depends(get_db), u=Depends(admin_only)):
    r = db.get(KeyRotation, rotation_id)
    if not r:
        raise HTTPException(404, '轮换单据不存在')
    if r.status == 'completed':
        raise HTTPException(409, '该轮换已完成，无需重试')
    count = rotation.retry_failed(db, r)
    record(db, u.email, 'key.rotation.retry', {'id': r.id, 'retried': count})
    db.commit()
    return rotation.rotation_summary(db, r)
