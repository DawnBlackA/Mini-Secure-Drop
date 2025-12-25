# MiniSecureDrop

基于 Web 的端到端加密文件共享系统。前端使用 WebCrypto 在本地完成 AES‑GCM 256 加密与解密，服务端仅保存密文与少量元数据；身份鉴权采用 JWT（HS256），并提供基础的速率限制与恶意模式拦截。

## 快速开始

1) 安装依赖（推荐 pnpm）：

```bash
pnpm install
```

2) 启动开发服务：

```bash
pnpm dev
```

3) 打开页面（根路径即功能页）：

- 访问 http://localhost:3000 上传/下载端到端加密文件。

## 架构与数据流

前端（浏览器）负责所有明文处理；服务端永不接触明文，也不保存密钥材料。

- 加密上传（客户端完成）：
	1. 读取文件为 ArrayBuffer；
	2. 生成 16 字节随机 `salt` 与 12 字节随机 `iv`；
	3. 使用 PBKDF2(SHA‑256, 120000 次, 32 字节) 从用户口令派生 AES‑GCM(256) 密钥；
	4. 使用 AES‑GCM 加密，得到密文 `cipher`；
	5. 将 `[salt | iv | cipher]` 二进制拼接作为请求体上传（`application/octet-stream`）。
- 下载解密（客户端完成）：
	1. 下载密文；
	2. 拆出 `salt` 与 `iv`；
	3. 用同一口令 + `salt` 再次 PBKDF2 派生密钥；
	4. 使用 AES‑GCM 解密复原文件并触发浏览器下载。

源码位置：客户端页面在 [pages/index.tsx](pages/index.tsx)，上传/下载交互、WebCrypto 逻辑与 UI 均在此文件中。

## 加解密实现（客户端）

- 口令派生：`PBKDF2(SHA-256, iterations=120000, keyLen=256bit)`；
- 随机参数：`salt` 16 字节，`iv` 12 字节（符合 GCM 推荐）；
- 加密算法：`AES-GCM`；
- 组合格式：上传内容为 `[salt(16) | iv(12) | cipher(n)]`；
- 对应源码：
	- 口令派生、加解密与拼接流程均在 [pages/index.tsx](pages/index.tsx) 中的 `deriveAesGcmKey()`、`encryptFile()`、`decryptToBlob()`。

注意：服务端只保留密文和这两个“非机密参数”（salt/iv），从不保存口令或派生密钥。

## 身份认证与访问控制

- JWT（HS256）：
	- 签发与校验在 [lib/jwt.ts](lib/jwt.ts)；默认过期 `1h`；密钥从环境变量 `JWT_SECRET` 读取（开发默认值可用，生产务必更换强随机）。
	- 前端登录/注册成功后保存 `token` 到 `localStorage`，后续以 `Authorization: Bearer <token>` 访问 API。
- 用户持久化：
	- 用户注册会写入 `storage/users.json`；字段包括 `username`、`id`、`salt`、`hash`（PBKDF2 后）与 `iterations`；
	- 相关逻辑在 [lib/users.ts](lib/users.ts)，通过 `loadUsersSync()/saveUsersSync()` 在重启后仍可登录。
- 资源授权：
	- 文件 `id` 命名包含所有者前缀：`<ownerId>__<随机>`；
	- 读取/下载会校验 `id` 必须以 `JWT.sub` 开头，防止越权访问；参见 [lib/storage.ts](lib/storage.ts) 与 API 路由实现。

## 入侵防护（基础）

- 速率限制：10 秒内每 IP 超过 30 次请求直接 429；
- 恶意模式拦截：拦截常见 SQLi/XSS 特征（如 `union select`、`<script`、`1=1`、`onerror=` 等）；
- 对应实现：见 [lib/security.ts](lib/security.ts)；在各 API 路由中引入执行。

### 入侵防护测试（在主页可一键触发）

主页已集成两个测试按钮（[pages/index.tsx](pages/index.tsx)）：

- 恶意输入拦截测试：向注册接口提交含 `<script>` 的用户名，预期返回 HTTP 400（被基础拦截器阻断）。
- 速率限制测试：在 10 秒窗口内连续发送 35 次请求（已登录用 `/api/list`，未登录用 `/api/login`），统计 429 次数；出现 429 说明速率限制生效。

也可用命令行模拟（需先启动服务 `pnpm dev`）：

```bash
# 恶意输入拦截：预期返回 400
curl -i -H "Content-Type: application/json" \
	-d '{"username":"<script>alert(1)</script>","password":"secret123"}' \
	http://localhost:3000/api/register

# 速率限制（示例：对 login 连发 35 次）
for i in $(seq 1 35); do \
	curl -s -o /dev/null -w "%{http_code}\n" -H "Content-Type: application/json" \
		-d '{"username":"dummy","password":"dummy"}' \
		http://localhost:3000/api/login; \
done
```

## 存储设计

- 存储根目录：项目根下 `storage/`；
- 用户信息：`storage/users.json`（JSON 数组）；
- 文件密文：按所有者分目录保存，路径 `storage/<ownerId>/`；
	- 密文：`<ownerId>__<随机>.bin`
	- 元数据：同名 `*.json`，包含 `id/owner/originalName/size/createdAt`
- 读写工具：
	- [lib/storage.ts](lib/storage.ts)
		- `saveCipher(owner, originalName, data)`：落盘密文并生成元数据
		- `listCiphers(owner)`：按创建时间倒序列出
		- `readCipher(owner, id)`：带前缀校验读取
		- `removeCipher(owner, id)`：删除文件与元数据

## API 设计

所有受保护 API 需携带 `Authorization: Bearer <token>`（除了注册/登录）。

1) 注册：`POST /api/register`

请求：`{ username: string, password: string }`

响应：`{ token, userId, username }`

源码：[pages/api/register.ts](pages/api/register.ts)

2) 登录：`POST /api/login`

请求：`{ username: string, password: string }`

响应：`{ token, userId, username }`

源码：[pages/api/login.ts](pages/api/login.ts)

3) 上传密文：`POST /api/upload`

请求头：

```
Content-Type: application/octet-stream
X-File-Name: <原始文件名>
Authorization: Bearer <token>
```

请求体：二进制 `[salt|iv|cipher]`（最大 20 MB 演示限制）

响应：`{ id, originalName, size, createdAt }`

源码：[pages/api/upload.ts](pages/api/upload.ts)（注意关闭 `bodyParser` 以接收原始二进制）

4) 列出文件：`GET /api/list`

响应：`Array<{ id, owner, originalName, size, createdAt }>`（仅当前用户）

源码：[pages/api/list.ts](pages/api/list.ts)

5) 下载密文：`GET /api/download?id=<fileId>`

响应：`application/octet-stream`（与上传格式一致）

源码：[pages/api/download.ts](pages/api/download.ts)

## 前端页面

- 单页入口：[pages/index.tsx](pages/index.tsx)
	- 账号与会话：注册/登录/退出，`localStorage` 持久化 `token` 与 `username`
	- 本地加密上传：WebCrypto 生成 `salt/iv`，PBKDF2 派生 AES‑GCM 密钥后加密
	- 列表与下载：调用 API 获取元数据、下载密文并本地解密为 Blob 触发下载

## 运行与调试

```bash
pnpm install
pnpm dev
```

可选环境变量：

- `JWT_SECRET`：JWT 签名密钥（强随机值，生产必设）
- `JWT_EXPIRES_IN`：JWT 有效期（默认 `1h`）

## 安全注意事项与扩展建议

- 强口令策略：用户口令强度直接影响离线暴力破解成本。
- 提升口令哈希成本：可将 PBKDF2 迭代提高到 ≥300k，或在服务端用户哈希改用 `scrypt`/`Argon2id`。
- 服务端 Pepper（可选）：在服务端引入不入盘的全局 Pepper（环境变量）参与用户口令哈希。
- 账户防爆破：在登录接口加入用户级失败计数与锁定/退避逻辑。
- 存储与版本控制：建议将 `storage/` 加入版本忽略，并确保文件权限最小化；生产采用数据库与对象存储（可结合 KMS）。
- 传输安全：生产必须部署在 HTTPS 之上，并设置严格的 CORS、Cookie/Headers 策略。

## 技术栈与约束

- Next.js（Pages Router）、TypeScript、Tailwind CSS
- WebCrypto API：AES‑GCM、PBKDF2（浏览器端）
- JSON/文件系统（演示版服务端存储）
- 不改变现有 React/Next 版本

---

本项目为演示级实现，用于学习与教学。生产环境请结合数据库、对象存储、完善的审计与告警体系，并强化口令哈希策略与运维安全策略。
