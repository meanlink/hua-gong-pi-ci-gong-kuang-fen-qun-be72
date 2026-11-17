# 化工批次工况分群

KMeans 聚类的真实业务分析小型项目。完整模拟客户、痛点、上下游、算法公式与一天工作剧本见 [BUSINESS.md](BUSINESS.md)。

## 模块与业务流程
数据接入（JSON/CSV、字段验证、批次指纹）→ 参数化分析（异步 Python worker）→ 结果复核（指标、图形、明细、解释、批准）→ 定时分发（本地收件箱、CSV/JSON、SHA256）；另有业务总览和审计轨迹。
三个贯穿全栈的实体：Dataset 数据批次、Job 分析任务、Report 分发计划；辅助 User、Audit、Delivery。

## 快速启动
```bash
cp .env.example .env
docker compose up -d --build --wait
docker compose exec -T backend python -m scripts.seed_demo
```
访问 http://localhost:18209；后端文档 http://localhost:19209/docs；数据库宿主端口 17709。
`SEED_DEMO=true` 自动幂等 seed；不覆盖用户修改。手动 seed 命令可重复执行。

## 演示账号与权限
|账号|密码|真实权限|
|---|---|---|
|admin@demo.local|Demo123!|接入、执行、批准、分发、暂停、读取与下载|
|analyst@demo.local|Demo123!|接入、执行、读取与下载；不能批准或安排分发|
|viewer@demo.local|Demo123!|只读与下载|

## 技术与本地开发
Python 3.12 / FastAPI / SQLAlchemy / NumPy / SciPy / scikit-learn；MySQL 8.0；Redis 7；Nginx；原生 HTML CSS JavaScript ES modules（用户指定）。后端所有校验、持久化和算法在服务端。无前端打包步骤。
后端：安装 backend/requirements.txt，设置 DATABASE_URL、REDIS_URL、JWT_SECRET、ARTIFACT_DIR、KEYRING_DIR 后在 backend/ 执行 `python -m migrations.initial`、`python -m scripts.seed_demo`、`uvicorn src.main:app`，另开 `python -m src.worker`。前端使用带 /api 反向代理的 Nginx，直接打开 index.html 不支持 API。

## 静态加密与密钥轮换
原始工况（datasets.records）、分析参数与结果（jobs.params/result）以及简报产物（CSV/JSON 文件）全部以 AES-256-GCM 认证加密静态落盘，信封格式 `enc::v1::<key_id>::<nonce|密文|标签>`，AAD 绑定具体字段。密钥材料保存在独立 `keyring-data` 卷（`KEYRING_DIR`），数据库与产物中只出现密钥 ID，密钥绝不随业务数据保存。
- 页面「密钥与加密」（仅管理员可发起）可发起轮换、查看每个轮换单的总量/已迁/待迁/失败进度与失败对象明细，并对失败对象重试；进行中的轮换每 3 秒自动刷新。
- 轮换先切换当前密钥：切换后所有新接入、计算结果与简报立即用新密钥；旧内容仍可正常读取，接入、计算、简报全程不停机。
- worker 按 `ROTATION_BATCH_SIZE`（默认 20）分批迁移存量与在途内容，单据和明细持久化在数据库。中断后从未迁/失败对象接着恢复；重复发起返回同一单据，重试不新增轮换、不丢失记录。在途写入与迁移并发时以列内密文信封的实际密钥 ID 为准并加行锁，旧密钥内容绝不会被重新落盘。
- 仅当全部对象迁移完成、复核确认无旧密钥信封与明文残留后才停用旧密钥（材料保留仅用于应急解密）；停用后原有分析与下载照常可用。
- 密文损坏或密钥缺失时后端明确拒绝（422/503），先完整解密成功才响应下载，绝不输出半份结果。历史明文数据与产物保持可读，并由轮换流程逐步加密。

## 目录与工程约定
backend/src/{models,schemas,services,routes,controllers,middlewares,constants,config,utils}；backend/scripts/seed_demo.py；backend/migrations/initial.py。
frontend/src/{api,stores,types,components/common,hooks,pages,router,utils,constants}。
Role 枚举：admin/analyst/viewer；JobStatus：queued/running/completed/failed。后端 backend/src/constants/enums.py，前端 frontend/src/constants/enums.js；路由权限在 middlewares/auth.py；页面按相同角色控制操作入口。

## 环境变量与 Docker
COMPOSE_PROJECT_NAME=batch-clusters；FRONTEND_PORT=18209；BACKEND_PORT=19209；DB_PORT=17709；DB_PASSWORD、JWT_SECRET 见 .env.example；SEED_DEMO 默认 true。共享命名产物卷供后端下载与 worker 写入，数据库/Redis 各持久卷，另有独立 keyring-data 卷只保存密钥材料（与业务数据物理分离）。
恰好五服务均有健康检查。Redis 队列加 SQL 排队状态兜底；worker 按 next_run 生成本地收件箱文件。周期 60 秒至 30 天。分发结果为批准分析的固定快照；若需新数据重新计算并建立新计划。当前不连接邮件或企业聊天。
错误响应、请求编号、Redis 每 IP 每分钟 240 次限流、JWT 和数据库操作审计。演示密钥与密码仅供本机模拟；生产部署前配置独立密钥与账号。

## 数据与验收
所有数据为固定随机种子生成的模拟业务数据，不能作为实际生产决策证据。项目独立算法、输入边界及业务局限详见 BUSINESS.md。测试与截图统一存放 ../../test-artifacts/gb-1010/，源码不含日志/截图/测试报告。
清理本项目演示数据：`docker compose down -v --remove-orphans`（会删除本项目命名卷）。

## License
MIT，见 LICENSE。
