# Cloudflare Bypass Tool 2026

基于 SeleniumBase UC Mode 的 Cloudflare Turnstile 验证绕过工具

A Cloudflare Turnstile bypass tool based on SeleniumBase UC Mode

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Mac%20%7C%20Windows%20%7C%20Linux-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 推荐代理 / Recommended Proxy

[![Swiftproxy](swiftproxy-banner.png)](https://www.swiftproxy.net/?ref=cloudflarebypass)

**Swiftproxy** —— 全球住宅代理服务平台，拥有 **8000万+** 高质量住宅 IP，覆盖 **190+** 国家和地区。支持 **HTTP/HTTPS/SOCKS5**、动态轮换与会话保持，流量不过期，并提供免费测试。凭借真实住宅 IP 和稳定连接，可有效提升数据采集、自动化访问、AI 工作流及大规模网络任务的成功率。

链接：<https://www.swiftproxy.net/?ref=cloudflarebypass>

---

## 免责声明 / Disclaimer

本工具仅供学习研究使用，请遵守相关法律法规和目标网站的服务条款。

This tool is for educational purposes only. Please comply with applicable laws and website terms of service.

---

## 功能特点 / Features

| 功能 | 说明 |
|:---|:---|
| SeleniumBase UC Mode | 操作系统级鼠标模拟，绕过率最高 |
| 单浏览器模式 | 简单可靠，资源占用低 |
| 并行模式 | 多浏览器同时运行，提高效率 |
| 代理轮换 | 支持从文件批量加载代理 |
| HTTPS隧道检测 | 自动验证代理是否支持HTTPS |
| 跨平台 | Mac / Windows / Linux |
| Cookie保存 | JSON + Netscape 双格式 |

---

## 快速开始 / Quick Start

```bash
# 安装
pip install seleniumbase

# 基础用法（推荐）
python bypass.py https://example.com

# 使用代理
python bypass.py https://example.com -p http://127.0.0.1:7890
```

---

## 安装部署 / Installation

### Mac / Windows

```bash
git clone https://github.com/1837620622/cloudflare-bypass-2026.git
cd cloudflare-bypass-2026
pip install -r requirements.txt
```

### Linux (Ubuntu/Debian)

```bash
# 方式1: 一键安装
git clone https://github.com/1837620622/cloudflare-bypass-2026.git
cd cloudflare-bypass-2026
sudo bash install_linux.sh

# 方式2: 手动安装
sudo apt-get update
sudo apt-get install -y xvfb libglib2.0-0 libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libgbm1 libasound2

# 安装Chrome
wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
sudo apt-get install -f -y

# Python依赖
pip install seleniumbase pyvirtualdisplay
```

---

## 使用方法 / Usage

本工具提供 **4 种不同技术方案的绕过策略**，根据场景选择：

| 文件 | 方案 | 原理 | 场景 |
|:---|:---|:---|:---|
| `bypass.py` | SeleniumBase UC Mode | 操作系统级鼠标模拟 + Chrome | 综合推荐，绕过率最高 |
| `simple_bypass.py` | SeleniumBase + 并行 | 多浏览器并行 + 代理轮换 | 批量采集、分布式任务 |
| `bypass_nodriver.py` | CDP 直连 | 无 WebDriver，直接 CDP 通信 | SeleniumBase替代，内置cf_verify() |
| `bypass_curl_cffi.py` | TLS 指纹仿冒 | HTTP层JA3/JA4指纹修改 | API绕过、无需浏览器、超轻量 |

---

### 1. 简单模式 (bypass.py) - 推荐

单浏览器，简单可靠：

```bash
# 直连
python bypass.py https://example.com

# 使用代理
python bypass.py https://example.com -p http://127.0.0.1:7890

# 设置超时
python bypass.py https://example.com -t 60
```

**参数：**

| 参数 | 说明 | 默认值 |
|:---|:---|:---:|
| `url` | 目标URL | 必填 |
| `-p, --proxy` | 代理地址 | 无 |
| `-t, --timeout` | 超时(秒) | 60 |
| `--no-save` | 不保存Cookie | 否 |

---

### 2. 完整模式 (simple_bypass.py)

支持并行和代理轮换：

```bash
# 直连模式
python simple_bypass.py https://example.com

# 指定代理
python simple_bypass.py https://example.com -p http://127.0.0.1:7890

# 代理轮换模式（顺序尝试proxy.txt中的代理）
python simple_bypass.py https://example.com -r -f proxy.txt

# 并行模式（3个浏览器同时运行）
python simple_bypass.py https://example.com -P -b 3 -t 60

# 并行 + 代理检测 + 30批次
python simple_bypass.py https://example.com -P -c -b 3 -t 15 -n 30 -f proxy.txt
```

**参数：**

| 参数 | 说明 | 默认值 |
|:---|:---|:---:|
| `url` | 目标URL | 必填 |
| `-p, --proxy` | 指定代理地址 | 无 |
| `-f, --proxy-file` | 代理文件路径 | proxy.txt |
| `-r, --rotate` | 顺序代理轮换模式 | 否 |
| `-P, --parallel` | 并行模式 | 否 |
| `-b, --batch` | 并行浏览器数量 | 3 |
| `-t, --timeout` | 超时时间(秒) | 60 |
| `-n, --retries` | 最大批次/重试数 | 3 |
| `-c, --check-proxy` | 预检测代理存活 | 否 |
| `--no-save` | 不保存Cookie | 否 |

---

### 3. Python API

```python
# 简单模式
from bypass import bypass_cloudflare

result = bypass_cloudflare("https://example.com")
if result["success"]:
    print(f"cf_clearance: {result['cf_clearance']}")
    print(f"User-Agent: {result['user_agent']}")

# 完整模式
from simple_bypass import bypass_cloudflare, bypass_parallel

# 单次绕过
result = bypass_cloudflare("https://example.com", proxy="http://127.0.0.1:7890")

# 并行绕过
result = bypass_parallel(
    url="https://example.com",
    proxy_file="proxy.txt",
    batch_size=3,
    timeout=15.0,
    max_batches=30
)
```

---

### 4. nodriver 方案 (bypass_nodriver.py) — SeleniumBase 替代

基于 CDP 协议直连 Chrome，无需 WebDriver。nodriver 是 undetected-chromedriver 的官方继任者。

```bash
# 安装
pip install nodriver

# 直连
python bypass_nodriver.py https://example.com

# 使用代理
python bypass_nodriver.py https://example.com -p http://127.0.0.1:7890

# 启用无头模式 (不推荐)
python bypass_nodriver.py https://example.com --headless
```

**特点：** 不依赖 Selenium/WebDriver，内置 `cf_verify()` 自动处理验证点击。

---

### 5. TLS 指纹方案 (bypass_curl_cffi.py) — 超轻量

在 HTTP/TLS 层仿冒真实浏览器的 JA3/JA4 指纹，不需要启动浏览器。

```bash
# 安装
pip install curl_cffi

# 基础使用
python bypass_curl_cffi.py https://example.com

# 使用代理
python bypass_curl_cffi.py https://example.com -p http://127.0.0.1:7890

# 切换指纹类型 (chrome120/chrome124/chrome131/firefox121/safari17_0/edge101)
python bypass_curl_cffi.py https://example.com -f firefox121

# 增加重试次数
python bypass_curl_cffi.py https://example.com -n 5
```

**特点：** 极速、零浏览器依赖、适合服务器环境和 API 调用场景。但对于需要交互式验证的页面可能不适用。

---

## 代理文件格式 / Proxy Format

`proxy.txt` 每行一个代理：

```
# 支持的格式
127.0.0.1:7890
http://127.0.0.1:7890
socks5://127.0.0.1:1080
http://user:pass@host:port
```

---

## 输出文件 / Output

Cookie保存到 `output/cookies/` 目录：

| 文件 | 格式 | 用途 |
|:---|:---|:---|
| `cookies_*.json` | JSON | 编程使用 |
| `cookies_*.txt` | Netscape | curl -b 使用 |

**JSON示例：**
```json
{
  "url": "https://example.com",
  "cookies": {
    "cf_clearance": "xxx..."
  },
  "user_agent": "Mozilla/5.0...",
  "timestamp": "20260122_103000"
}
```

---

## 项目结构 / Structure

```
cloudflare-bypass-2026/
├── bypass.py              # 方案1: SeleniumBase 单浏览器（推荐）
├── simple_bypass.py       # 方案2: SeleniumBase 并行+代理轮换
├── bypass_nodriver.py     # 方案3: nodriver CDP直连
├── bypass_curl_cffi.py    # 方案4: curl_cffi TLS指纹仿冒
├── bypass_seleniumbase.py # 详细版（类封装实现）
├── install_linux.sh       # Linux安装脚本
├── requirements.txt       # Python依赖
├── proxy.txt              # 代理列表
├── output/                # Cookie输出目录
└── README.md
```

---

## 常见问题 / FAQ

**Q: 为什么不用无头模式?**
> Cloudflare可检测无头浏览器，建议保持可视化模式以获得最高成功率。

**Q: cf_clearance有效期?**
> 通常30分钟到数小时，建议过期前重新获取。

**Q: Linux报错 "X11 display failed"?**
> 运行 `sudo bash install_linux.sh` 安装Xvfb等依赖。

**Q: 代理不工作?**
> 大部分公共代理不支持HTTPS隧道。建议使用直连模式或购买高质量住宅代理。

**Q: Chrome启动多个进程?**
> 这是Chrome正常架构（主进程+渲染进程+GPU进程），非代码问题。

---

## 技术参考 / References

- [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/)
- [SeleniumBase UC Mode](https://seleniumbase.com/)

---

## License

MIT License - 2026

---

**如果这个项目对你有帮助，请给个 Star!**

**If this project helps you, please give it a Star!**
