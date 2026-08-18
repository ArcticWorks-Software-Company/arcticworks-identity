<div align="center">
	<h1>ArcticWorks Identity</h1>
	<p>ArcticWorks 生态的集中式身份与访问平台。</p>
</div>

[English](README.md) · [简体中文](README.zh-CN.md)

[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![CI](https://github.com/ArcticWorks-Software-Company/arcticworks-identity/actions/workflows/ci.yml/badge.svg)](https://github.com/ArcticWorks-Software-Company/arcticworks-identity/actions/workflows/ci.yml)

## ArcticWorks Identity 是什么？

Identity 是 ArcticWorks 软件生态的唯一信任根。它管理三类身份：人、服务（服务账户）和设备。它向 ArcticWorks 产品签发标准兼容的凭据（OIDC / OAuth 2.0、WebAuthn），每个产品都直接通过 Identity 认证。没有任何产品依赖其他产品完成认证。Identity 不包含任何产品特定的业务逻辑。

### 功能

- 👤 账户、组织、团队和基于角色的访问控制
- 🔐 OIDC 和 OAuth 2.0
- 🖐️ WebAuthn 通行密钥和机器身份
- 📜 审计跟踪
- 🧩 面向 ArcticWorks 应用的 TypeScript SDK

## 仓库结构

| 路径 | 内容 |
|---|---|
| `apps/api` | Rust（Axum）后端：账户、组织/团队、RBAC、OIDC、通行密钥、机器身份、审计 |
| `apps/web` | 基于 ArcticWorks 设计系统的 SvelteKit 前端 |
| `packages/identity-sdk` | 面向 ArcticWorks 应用的 TypeScript SDK |
| `examples/continuity-mock` | 演示 OIDC 登录和权限检查的模拟产品应用 |
| `e2e` | Playwright 端到端套件（完整演示流程） |
| `docs` | 架构、威胁模型、开发与部署指南 |
| `compose.yaml` | 本地开发基础设施（Postgres、Valkey、Mailpit） |

## 安装与运行

```sh
docker compose up -d          # postgres + valkey + mailpit
npm install                   # 安装工作区依赖
npm run db:migrate            # 应用数据库迁移
npm run db:seed               # 开发管理员 + 测试 OIDC 客户端
npm run dev:api               # API 位于 http://localhost:8080
npm run dev:web               # Identity 界面位于 http://localhost:5173
npm run dev:mock              # 模拟产品应用位于 http://localhost:5174
```

完整指南见 [docs/development.md](docs/development.md)。

## 文档

- [架构](docs/architecture.md)
- [威胁模型](docs/threat-model.md)
- [开发](docs/development.md)
- [部署](docs/deployment.md)

## 许可证

MIT。见 [LICENSE](LICENSE)。
