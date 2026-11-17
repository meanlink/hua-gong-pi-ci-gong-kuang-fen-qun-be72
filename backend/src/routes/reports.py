import io
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from src.config.database import get_db
from src.models import Report, Delivery
from src.schemas.report import ReportInput
from src.middlewares.auth import current_user, admin_only
from src.services import reports
from src.services.audit import record
from src.utils.serialization import report_dict, delivery_dict
router = APIRouter()


@router.get('/reports')
def listing(db=Depends(get_db), u=Depends(current_user)):
    return [report_dict(r) for r in db.scalars(select(Report).order_by(Report.id.desc()))]


@router.post('/reports', status_code=201)
def create(data: ReportInput, db=Depends(get_db), u=Depends(admin_only)):
    r = reports.create(db, data)
    record(db, u.email, 'report.schedule', {'id': r.id, 'destination': r.destination})
    db.commit()
    return report_dict(r)


@router.post('/reports/{id}/toggle')
def toggle(id: int, db=Depends(get_db), u=Depends(admin_only)):
    r = db.get(Report, id)
    if not r:
        raise HTTPException(404, '分发计划不存在')
    r.enabled = not r.enabled
    record(db, u.email, 'report.toggle', {'id': id, 'enabled': r.enabled})
    db.commit()
    return report_dict(r)


@router.get('/deliveries')
def deliveries(db=Depends(get_db), u=Depends(current_user)):
    return [delivery_dict(d) for d in db.scalars(select(Delivery).order_by(Delivery.id.desc()).limit(100))]


@router.get('/deliveries/{id}/download')
def download(id: int, format: str = 'csv', db=Depends(get_db), u=Depends(current_user)):
    d = db.get(Delivery, id)
    if not d:
        raise HTTPException(404, '归档不存在')
    if format not in ('csv', 'json'):
        raise HTTPException(422, '支持 CSV 或 JSON')
    # 先完整解密成功再响应，任何损坏都显式拒绝，绝不输出半份结果
    content = reports.read_artifact(d.filename, '.json' if format == 'json' else '')
    filename = d.filename + ('.json' if format == 'json' else '')
    media = 'application/json' if format == 'json' else 'text/csv; charset=utf-8'
    return StreamingResponse(io.BytesIO(content), media_type=media,
                             headers={'Content-Disposition': f'attachment; filename="{filename}"'})
