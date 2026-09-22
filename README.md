# 灾备密钥分片 API（Shamir Secret Sharing + FastAPI + SQLite）

将灾备恢复密钥按 **Shamir (t, n) 阈值方案**拆分为 `n` 份分片：任意不少于
`t` 份分片即可重建密钥，少于 `t` 份不泄露任何信息。服务仅保存**校验摘要**，
不保存密钥本身，也不保存原始分片。

- 框架：FastAPI + Uvicorn（监听 **8000** 端口）
- 存储：SQLite（零外部依赖、无需任何账号）
- 密码学：GF(2⁸) 上逐字节 Shamir 秘密分享，随机系数由 `secrets` 生成
- 容器化：Dockerfile + docker-compose，启动时自动初始化数据库

## 安全模型

| 要点 | 说明 |
| --- | --- |
| 分片只返回一次 | 创建会话的响应里一次性返回全部分片，之后无法再查询或重新获取 |
| 只存摘要 | 数据库保存密钥 SHA-256、以及每个分片绑定会话 ID 的 SHA-256 摘要；原始密钥/分片不落盘 |
| 错误分片不泄密 | 提交时**逐片先做完整性校验**，只有校验通过的分片才参与拉格朗日插值；伪造/篡改分片被拒绝，无法影响重建结果 |
| 重建结果复核 | 重建后的密钥再与存储摘要做常量时间比对，不一致绝不返回 |
| 密钥只展示一次 | 恢复成功后密钥仅在当次响应出现；重复提交返回 `replay: true` 且 `key: null` |
| 会话可撤销 | 撤销后任何提交分片请求被拒绝（409）；撤销操作本身幂等 |
| 会话可轮换 | 凭达到旧阈值且校验通过的分片，可在**同一事务**中以新 `(t, n)` 重新分片：旧会话转为 `rotated` 并永久拒绝恢复，新会话分片只返回一次；轮换失败不留任何副作用 |
| 操作幂等 | 创建会话支持 `Idempotency-Key`（请求头或请求体）；同键同参数重放返回同一会话且不再返回分片；同键不同参数返回 409 |
| 防篡改审计链 | 创建、分片提交、恢复成功、撤销与轮换均在**原业务事务内**追加审计事件；事件只含会话标识/类型/UTC 时间/非敏感结果与计数，绝不包含密钥、分片或摘要。事件按连续序号以 `SHA-256(prev_hash + 规范化内容)` 串联，历史字段或前序哈希一旦被改动即可定位首个失效序号 |
| 可选 API Key | 设置 `DR_API_KEY` 后，`/api/v1/*` 需携带 `X-API-Key`（默认关闭，开箱即用） |

> 注意：按阈值方案设计，**重建所需的全部 `t` 份分片必须在同一次提交请求中给出**
> （服务不持久化分片内容，无法跨请求累积分片）。会话状态接口会记录已验证的
> 分片索引，仅用于进度展示。

## 目录结构

```
.
├── app/
│   ├── main.py        # FastAPI 路由、请求/响应模型、鉴权
│   ├── sharing.py     # Shamir 拆分/重建、分片令牌编解码
│   ├── gf256.py       # GF(2^8) 有限域运算（AES 多项式 0x11b）
│   ├── audit.py       # 审计事件规范化、SHA-256 哈希链与整链校验
│   └── database.py    # SQLite 建表、事务与审计链追加
├── tests/             # pytest：100+ 用例（域运算/拆分/API/轮换/审计链/安全场景）
├── entrypoint.sh      # 启动前初始化数据库，然后起 uvicorn
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 快速开始（Docker Compose）

```bash
docker compose up -d --build
curl http://localhost:8000/health
# {"status":"ok"}
```

数据库文件位于命名卷 `ss_data`（容器内 `/data/sss.db`），首次启动时由
`entrypoint.sh` 自动建表。

可选：在 `docker-compose.yml` 中打开 `DR_API_KEY`，随后所有请求加
`-H 'X-API-Key: <token>'`。

## 本地直接运行

```bash
python -m pip install -r requirements.txt
export DR_DB_PATH=./data/sss.db          # 默认值即此
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

交互式文档（无需账号）：<http://localhost:8000/docs> 与 <http://localhost:8000/redoc>。

## API 概览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET  | `/health` | 健康检查（无需 API Key） |
| POST | `/api/v1/sessions` | 创建恢复会话，一次性返回 n 个分片 |
| GET  | `/api/v1/sessions/{id}` | 查询会话状态与已提交分片索引（含 `replacement_session_id`） |
| POST | `/api/v1/sessions/{id}/shares` | 校验分片并在达到阈值时重建密钥 |
| POST | `/api/v1/sessions/{id}/rotate` | 凭旧阈值分片以新 `(t, n)` 轮换会话（幂等、事务性） |
| POST | `/api/v1/sessions/{id}/revoke` | 撤销会话（幂等） |
| GET  | `/api/v1/sessions/{id}/audit` | 按序返回审计事件及整链校验状态（含首个失效序号） |

所有错误响应统一为：

```json
{ "error": { "code": "session_not_found", "message": "...", "details": null } }
```

### 1. 创建会话并获取分片

```bash
curl -s -X POST http://localhost:8000/api/v1/sessions \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: ticket-2026-09-21-001' \
  -d '{
        "secret": "postgres-root-password",
        "encoding": "utf-8",
        "threshold": 3,
        "total": 5
      }'
```

请求体：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `secret` | string | 待拆分密钥（最大 4096 字节） |
| `encoding` | `utf-8` / `hex` / `base64` | 密钥编码，默认 `utf-8`；重建时按原编码返回 |
| `threshold` | int (2–255) | 重建所需最小分片数 `t` |
| `total` | int (2–255) | 分片总数 `n`，需 `n >= t` |
| `idempotency_key` | string? | 也可用请求头 `Idempotency-Key` |

响应（`shares` 仅此一次）：

```json
{
  "session_id": "a1b2…",
  "status": "active",
  "threshold": 3,
  "total_shares": 5,
  "shares": ["base64url-令牌1", "…", "…"],
  "share_checksums": [
    {"index": 1, "digest": "sha256-hex…}
  ],
  "shares_returned": true,
  "replay": false
}
```

分片令牌是自描述的 `base64url(JSON[session_id, x, y])`，天然与该会话绑定。
`share_checksums` 可由保管方自行保存以便核验。

### 2. 提交分片、重建密钥

需在同一次请求中提交至少 `t` 份。

```bash
curl -s -X POST http://localhost:8000/api/v1/sessions/a1b2…/shares \
  -H 'Content-Type: application/json' \
  -d '{"shares": ["令牌1", "令牌2", "令牌3"]}'
```

成功（密钥只出现这一次）：

```json
{
  "session_id": "a1b2…",
  "status": "recovered",
  "recovered": true,
  "key": "postgres-root-password",
  "key_encoding": "utf-8",
  "key_digest": "…",
  "replay": false,
  "accepted_indices": [1, 2, 3],
  "rejected": []
}
```

含错误分片时，正确分片照常返回 accepted，错误分片进入 `rejected`
（`malformed_share` / `integrity_check_failed` / `duplicate_index_in_request`），
绝不参与插值；若有效分片不足阈值，`recovered: false` 且 `key: null`。

再次提交相同分片：`status: "recovered"`、`replay: true`、`key: null`。

### 3. 查询状态

```bash
curl http://localhost:8000/api/v1/sessions/a1b2…
```

返回 `active` / `recovered` / `revoked` / `rotated`、阈值、密钥摘要、已验证分片索引、
失败尝试计数与各时间戳。已轮换会话额外返回 `rotated_at` 与
`replacement_session_id`（指向接替的新会话），未轮换时该字段为 `null`。

### 4. 撤销会话（幂等）

```bash
curl -X POST http://localhost:8000/api/v1/sessions/a1b2…/revoke
# 再调一次仍为 200，status 保持 revoked，replay: true
```

撤销后提交分片返回 409 `session_revoked`。已恢复的会话不可撤销，调用返回
409 `session_not_revocable`。

### 5. 轮换会话（更换阈值与分片）

当分片可能泄露、保管人变动或需要调整阈值时，无需先恢复密钥即可**重新分片**：
提交达到**旧阈值**且完整性校验通过的分片，并指定新的 `new_threshold` /
`new_total`。服务在**同一事务**中：① 用旧分片重建密钥并以新参数重新拆分；
② 创建新会话（分片仅当次返回一次）；③ 把旧会话标记为 `rotated`，此后任何
针对旧会话的恢复请求一律拒绝（409 `session_rotated`）。任一步骤失败都会整体
回滚——旧会话状态不变，也不会留下新会话。

```bash
curl -s -X POST http://localhost:8000/api/v1/sessions/a1b2…/rotate \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: rotate-2026-09-22-001' \
  -d '{
        "shares": ["旧会话令牌1", "旧会话令牌2", "旧会话令牌3"],
        "new_threshold": 2,
        "new_total": 4
      }'
```

请求体：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `shares` | string[] | 旧会话的分片，数量需 ≥ 旧 `threshold`，且**全部**通过完整性校验 |
| `new_threshold` | int (2–255) | 新会话的重建阈值 `t′` |
| `new_total` | int (2–255) | 新会话的分片总数 `n′`，需 `n′ >= t′` |
| `idempotency_key` | string? | 也可用请求头 `Idempotency-Key` |

响应（新会话分片仅此一次）：

```json
{
  "old_session_id": "a1b2…",
  "old_status": "rotated",
  "session_id": "c3d4…",
  "status": "active",
  "threshold": 2,
  "total_shares": 4,
  "shares": ["新令牌1", "…", "…", "…"],
  "share_checksums": [{"index": 1, "digest": "sha256-hex…"}],
  "shares_returned": true,
  "replay": false
}
```

- 新会话与旧会话共享同一密钥（`key_digest` 不变），但分片是全新随机多项式
  生成的，旧分片对新会话无效。
- 重放相同 `Idempotency-Key` + 相同请求：返回 `replay: true`、`shares: null`，
  仅含新会话元数据；同一 key 搭配不同请求返回 409 `idempotency_conflict`。
- 分片校验失败（400 `share_verification_failed`）或数量不足旧阈值
  （400 `insufficient_shares`）时，旧会话保持 `active`，可继续正常使用。
- 已 `revoked` / `recovered` / `rotated` 的会话不可轮换，分别返回 409
  `session_revoked` / `session_not_rotatable` / `session_rotated`。
- 轮换可以链式进行：新会话之后仍可再次轮换。

### 6. 查询防篡改审计链

会话的每次状态变更都会在**原业务事务内**追加一条审计事件——创建会话、提交
分片（含部分提交与含错误分片的提交）、恢复成功、撤销、轮换。轮换会向旧会话
追加 `session_rotated`、同时向新会话追加 `session_created` 两条事件；幂等重放
与撤销重放是无状态变更的 no-op，不产生新事件。业务事务回滚（如轮换失败）时，
审计事件一并回滚。

```bash
curl http://localhost:8000/api/v1/sessions/a1b2…/audit
```

```json
{
  "session_id": "a1b2…",
  "events": [
    {
      "seq": 1,
      "type": "session_created",
      "timestamp": "2026-09-22T08:15:01.123456Z",
      "result": "created",
      "details": {"threshold": 3, "total_shares": 5, "created_by_rotation": false},
      "prev_hash": "",
      "event_hash": "565ad5a1…",
      "valid": true
    }
  ],
  "chain": {
    "hash_algorithm": "SHA-256",
    "valid": true,
    "event_count": 1,
    "first_invalid_seq": null,
    "failure_reason": null
  }
}
```

链式规则与事件词汇：

- `seq` 在**每个会话内**从 1 开始连续编号；`prev_hash` 为上一条事件的
  `event_hash`（首条为空串），`event_hash = SHA-256(prev_hash + 规范化事件内容)`。
  规范化内容为紧凑（无多余空白）、键名字典序排序的 JSON：
  `{"details":{…},"result":"…","seq":1,"session_id":"…","timestamp":"…","type":"…"}`。
- 并发写入由 `BEGIN IMMEDIATE` 写事务 + 进程锁串行化，并以
  `(session_id, seq)` 主键兜底：不会出现重复序号、空号或分叉。
- 事件类型：`session_created` / `shares_submitted` / `session_recovered` /
  `session_revoked` / `session_rotated`；结果词汇为非敏感的
  `created` / `pending` / `recovered` / `revoked` / `rotated`，`details` 只含
  阈值、分片总数、接受/拒绝计数等小整数和接替会话标识，**不含密钥、原始分片、
  令牌或任何摘要**。
- 校验按序重算哈希；任一历史字段（含 `details`、时间、类型、结果）或前序哈希
  被改动时，`chain.valid` 为 `false`，`first_invalid_seq` 指向**首个**失效序号，
  `failure_reason` 给出失效检查：`event_content_tampered`（规范化内容不一致）、
  `previous_hash_mismatch`（前序哈希被改）、`hash_mismatch`（事件哈希被改）或
  `gap_or_duplicate_sequence`（事件被删/序号重复）。校验始终以库中前序哈希继续
  向后比对，因此首个断点之后的事件不会被误报为新的首个断点。

## 幂等性说明

- **创建**：携带相同 `Idempotency-Key` 的重试返回同一个 `session_id`；首次响应
  才有分片，重放响应 `shares: null, replay: true`。同一 key 搭配不同的密钥/阈值
  参数返回 409 `idempotency_conflict`。
- **轮换**：同样支持 `Idempotency-Key`；同键同请求重放只返回新会话元数据
  （`shares: null`），同键不同请求返回 409。未携带 key 的轮换成功后无法重试——
  旧会话已转为 `rotated`，重复调用返回 409 `session_rotated`。
- **撤销**：重复撤销是无害的 no-op。
- **提交**：同一请求内重复索引被标记拒绝；恢复完成后重复提交不再次返回密钥。
- **服务重启**：表结构创建使用 `CREATE TABLE IF NOT EXISTS`，启动初始化可重复执行；
  旧版本数据库启动时自动补齐 `rotated_at` / `replacement_session_id` 列，并自动
  创建 `audit_events` 审计表（旧会话此前无事件，空链视为 valid）。

## 密码学实现说明

- 域：GF(2⁸)，模多项式 x⁸+x⁴+x³+x+1（0x11b，与 AES 相同），生成元 3。
- 拆分：密钥每个字节作为随机 `(t-1)` 次多项式常数项；系数来自
  `secrets.randbelow(256)`；分片 `y_i = f(i)`，索引 `x ∈ [1, n]`。
- 重建：对每个字节在 0 处做拉格朗日插值，逐字节恢复。
- 完整性：`share_digest = SHA256(session_id ‖ x ‖ '|' ‖ y)`，配合
  `hmac.compare_digest` 做常量时间比较。
- 审计链：`event_hash = SHA256(prev_hash ‖ 规范化事件内容)`，规范化事件内容为
  键名排序、无多余空白的 UTF-8 JSON（见上文「查询防篡改审计链」）。

## 配置项（环境变量）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `DR_DB_PATH` | `data/sss.db`（容器内 `/data/sss.db`） | SQLite 文件路径 |
| `DR_API_KEY` | 空（不鉴权） | 设置后对 `/api/v1/*` 强制 `X-API-Key` |

## 运行测试

```bash
python -m pip install pytest httpx
python -m pytest -q
```

测试覆盖：域运算恒等式、20 组随机拆分/任意阈值子集恢复、低于阈值无法恢复、
篡改/伪造/跨会话分片拒绝、恢复密钥只返回一次、撤销、创建与提交幂等、
轮换全流程（成功/失败回滚/幂等重放/冲突/链式轮换/旧库迁移）、
审计链（生命周期事件顺序、轮换双事件、回滚不留事件、哈希符合 SHA-256 规范、
字段/时间/前序哈希/删行等篡改定位首个失效序号、并发序号连续无分叉、
审计表不含密钥与原始分片、API Key 鉴权）等 100+ 断言。

## 部署注意事项

1. **立刻保存首次响应中的分片**：服务无法再次提供。
2. 生产建议开启 `DR_API_KEY`，并置于反向代理/TLS 之后（本服务自身不签发证书）。
3. 备份 `/data` 卷即可备份全部元数据；卷中不含密钥明文。
4. 阈值建议 `2 ≤ t ≤ n`，并按保管人数与抗共谋需求取值（如 3/5）。
