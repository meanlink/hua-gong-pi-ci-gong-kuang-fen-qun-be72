import time, json, logging
from pathlib import Path
from sqlalchemy import select
from redis import Redis
from src.config.database import Session
from src.config.settings import REDIS_URL
from src.models import Job, Dataset, Report
from src.services.business import analyze
from src.services.reports import deliver
from src.services.rotation import run_pending_rotations
from src.services.audit import record
from src.utils.crypto import CiphertextInvalidError, KeyMissingError

logging.basicConfig(level=logging.INFO)


def execute(job_id):
    with Session() as db:
        j = db.get(Job, job_id)
        if not j or j.status != 'queued':
            return
        j.status = 'running'
        db.commit()
        try:
            d = db.get(Dataset, j.dataset_id)
            # 读取原始工况即解密；若密文损坏或密钥缺失，任务明确失败而非产出半份结果
            result = analyze(d.records, j.params)
            json.dumps(result, allow_nan=False)
            # 计算完成后的在途写入：始终以当前（轮换后即为新）密钥落盘
            from src.utils.crypto import keyring
            j.result = result
            j.params = j.params
            j.crypto_key_id = keyring.current_key_id()
            j.status = 'completed'
            j.finished_at = time.time()
            record(db, 'worker', 'job.completed', {'id': j.id})
        except (CiphertextInvalidError, KeyMissingError) as exc:
            logging.error('分析任务 %s 因加密数据不可读失败：%s', job_id, exc)
            j.status = 'failed'
            j.error = str(exc)[:990]
            j.finished_at = time.time()
            record(db, 'worker', 'job.failed', {'id': j.id, 'reason': 'crypto'})
        except Exception as e:
            logging.exception('Analysis failed')
            j.status = 'failed'
            j.error = str(e)[:990]
            j.finished_at = time.time()
            record(db, 'worker', 'job.failed', {'id': j.id, 'error': j.error})
        db.commit()


def tick():
    with Session() as db:
        queued = list(db.scalars(select(Job.id).where(Job.status == 'queued').limit(3)))
    for job_id in queued:
        execute(job_id)
    with Session() as db:
        for r in db.scalars(select(Report).where(Report.enabled == True, Report.next_run <= time.time())):
            d = deliver(db, r)
            if d:
                record(db, 'worker', 'report.delivered', {'id': r.id, 'delivery': d.id})
        db.commit()
    # 轮换迁移与接入、计算、简报并行不悖：每轮只处理一小批，失败对象留待重试
    run_pending_rotations()


def main():
    r = Redis.from_url(REDIS_URL, socket_timeout=3)
    # This Compose stack has a single worker. A crash must not strand its jobs.
    with Session() as db:
        for j in db.scalars(select(Job).where(Job.status == 'running')):
            j.status = 'queued'
            record(db, 'worker', 'job.recovered', {'id': j.id})
        db.commit()
    while True:
        Path('/tmp/heartbeat').touch()
        try:
            item = r.blpop('analysis:queue', timeout=1)
            if item:
                execute(int(item[1]))
            tick()
        except Exception:
            logging.exception('Worker retry')
            time.sleep(2)


if __name__ == '__main__':
    main()
