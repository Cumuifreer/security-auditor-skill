---
name: security-auditor
description: 本地安全审计 Skill - 在安装第三方 Skills 前进行静态安全扫描,检测恶意代码模式、混淆payload、可疑命令组合等威胁。
user-invocable: true
metadata:
  {
    "openclaw":
      {
        "emoji": "🔒",
      },
  }
---

# Security Auditor Skill

在安装/更新第三方 Skills 之前进行静态安全扫描,防止恶意代码进入你的系统。

## 使用场景

当用户:
- 安装新的 skill (`clawhub install xxx`)
- 从 GitHub 手动拉取 skill
- 更新现有 skill
- 想检查某个 skill 目录是否安全

## 触发词

- "扫描这个 skill"
- "安全检查"
- "审核 skill"
- "检查安全性"
- "scan skill"
- "security audit"

## 使用方法

### 基本扫描

```bash
# 扫描当前目录的 skill
security-audit

# 扫描指定路径
security-audit /path/to/skill

# 扫描 ClawHub 安装的 skill
security-audit ~/.openclaw/skills/xxx
```

### 扫描模式

```bash
# 快速扫描 (仅关键危险)
security-audit --fast

# 完整扫描 (包括中低风险)
security-audit --full

# 输出 JSON 格式
security-audit --json
```

## 检测规则

### 🔴 CRITICAL (致命威胁)

| 模式 | 描述 |
|------|------|
| `curl \| bash` | 下载并直接执行远程脚本 |
| `curl > .bashrc` | 写入 shell 配置 |
| `curl > ~/.ssh` | 写入 SSH 密钥 |
| `wget \| bash` | 同 curl\|bash |
| `base64 -d \| bash` | 混淆后执行 |
| `chmod +x` + 网络下载 | 下载并赋予执行权限 |
| Gatekeeper bypass | `xattr -rd com.apple.quarantine` |

### 🟠 HIGH (高风险)

| 模式 | 描述 |
|------|------|
| `eval $(curl` | 远程代码注入 |
| `openssl ... | bash` | 下载并执行 OpenSSL |
| 加密货币钱包替换 | 替换钱包地址 |
| `sudo ...` 无确认 | 静默提权 |
| 导出凭据到远程 | `export CREDENTIALS` |

### 🟡 MEDIUM (中风险)

| 模式 | 描述 |
|------|------|
| Base64 编码块 >1KB | 可能的混淆 payload |
| 外部 API 密钥硬编码 | 可能的凭据泄露 |
| HTTP (非 HTTPS) | 不安全传输 |
| 未知二进制文件 | 可能的恶意程序 |

### 🟢 LOW (低风险/警告)

| 模式 | 描述 |
|------|------|
| 无 package.json 的 Node skill | 依赖不明 |
| 未知来源的二进制 | 需确认 |
| 敏感路径写入 | 需确认意图 |

## 输出示例

```
🔒 Security Audit Report
========================
Path: ~/.openclaw/skills/suspicious-skill
Date: 2026-02-22 19:30:00

CRITICAL: 2
  [!] curl | bash detected (install.sh:23)
  [!] base64 encoded payload >2KB (lib/utils.js:45)

HIGH: 1
  [!] Hardcoded API key (config.json:8)

MEDIUM: 3
  [!] HTTP URL found (api.js:12)
  [!] Unknown binary (bin/malware)

WHITELISTED: 5

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  RECOMMENDATION: DO NOT INSTALL
Found 2 CRITICAL threats. This skill appears malicious.
```

## 实现逻辑

### 1. 文件扫描

扫描以下文件类型:
- `*.sh` (Shell 脚本)
- `*.js`, `*.ts` (JavaScript/TypeScript)
- `*.py` (Python)
- `*.json` (配置文件)
- 二进制文件 (检测 magic numbers)

### 2. 模式匹配

使用正则表达式检测已知恶意模式:

```javascript
const CRITICAL_PATTERNS = [
  /curl\s*\|\s*bash/i,
  /wget\s*\|\s*bash/i,
  /base64\s+-d\s*\|\s*(bash|sh|zsh)/i,
  /eval\s*\$\(/i,
  /xattr\s+-r.*com\.apple\.quarantine/i,
];
```

### 3. 二进制检测

检测伪装成文本的二进制文件:

```javascript
const MAGIC_NUMBERS = {
  'exe': '4d5a',
  'mach-o': 'feedface',
  'elf': '7f454c46',
  'zip': '504b',
};
```

### 4. 上下文关联

检测危险命令组合:
- `curl` + `|` + `bash`
- `wget` + `chmod +x`
- `base64` + `eval`

### 5. 白名单机制

记录已知安全的 skill 特征哈希,减少误报:

```json
{
  "whitelist": [
    "skill-name:hash",
    "another-skill:hash"
  ]
}
```

## 依赖

无需额外依赖,使用系统原生工具:
- `grep` / `egrep` - 模式匹配
- `file` - 文件类型检测
- `xxd` / `hexdump` - 十六进制查看

## 安全哲学

> "Trust but Verify"

- 不执行代码,仅静态分析
- 宁可误报也不漏报
- 让用户做最终决定
- 持续更新检测规则
