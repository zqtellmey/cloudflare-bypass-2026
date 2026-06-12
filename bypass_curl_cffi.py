# ============================================================
# Cloudflare 绕过工具 - curl_cffi 方案 (仅限简单场景)
# 基于 TLS/JA3 指纹仿冒，HTTP协议层绕过，无需浏览器
# 支持 Mac / Windows / Linux
# ============================================================
# 
# ⚠️ 重要限制说明 ⚠️
# 
# 本方案仅能处理 TLS/JA3 指纹层面的检测，存在以下硬性限制:
#   1. 无法执行 JavaScript — Turnstile 必须依赖浏览器 JS 环境
#   2. 无法运行 Web API 探测 — Turnstile 会检查 navigator/webgl 等
#   3. 无法完成 PoW 计算 — Turnstile 后台运行 proof-of-work
#   4. 无法处理交互式验证 — Managed/Interactive 模式需要点击复选框
# 
# 适用场景:
#   - 旧版 Cloudflare "Under Attack" JS Challenge
#   - 简单的非交互式验证页面
#   - 低防护等级的站点
#
# 不适用场景:
#   - Cloudflare Turnstile (Managed / Non-Interactive / Invisible)
#   - 需要浏览器交互的任何验证
#   - 高防护等级的站点
#
# 建议: 如需绕过 Turnstile，请使用 bypass.py 或 bypass_nodriver.py
# ============================================================

import sys
import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

try:
    from curl_cffi import requests
    from curl_cffi.requests import BrowserTypeLiteral
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False
    # 降级到普通 requests，但绕过率会降低
    import requests as fallback_requests


# ============================================================
# 浏览器指纹配置
# 不同浏览器 TLS 指纹不同，可根据目标站点选择
# ============================================================
BROWSER_FINGERPRINTS = {
    "chrome120": {
        "impersonate": "chrome120",
        "name": "Chrome 120 (Windows)",
    },
    "chrome124": {
        "impersonate": "chrome124",
        "name": "Chrome 124 (Windows)",
    },
    "chrome131": {
        "impersonate": "chrome131",
        "name": "Chrome 131 (Windows)",
    },
    "firefox121": {
        "impersonate": "firefox121",
        "name": "Firefox 121 (Windows)",
    },
    "safari17_0": {
        "impersonate": "safari17_0",
        "name": "Safari 17.0 (macOS)",
    },
    "edge101": {
        "impersonate": "edge101",
        "name": "Edge 101 (Windows)",
    },
}

# Chrome 120 的真实 User-Agent 列表
USER_AGENTS_CHROME = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

# 标头模板 - 匹配所选浏览器指纹
def make_headers(user_agent: str) -> Dict[str, str]:
    """
    生成与浏览器指纹匹配的 HTTP 请求头
    
    参数:
        user_agent: 浏览器UA字符串
    
    返回:
        HTTP请求头字典
    """
    return {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }


def save_cookies_to_file(
    cookies_dict: Dict[str, str],
    url: str,
    user_agent: str,
    output_dir: str = "output/cookies"
) -> str:
    """
    保存Cookie到JSON和Netscape格式文件
    
    参数:
        cookies_dict: Cookie字典
        url: 目标URL
        user_agent: 浏览器UA
        output_dir: 输出目录
    
    返回:
        时间戳字符串
    """
    save_dir = Path(output_dir)
    save_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # JSON格式
    json_path = save_dir / f"cookies_curl_{ts}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "url": url,
            "cookies": cookies_dict,
            "user_agent": user_agent,
            "timestamp": ts,
            "method": "curl_cffi"
        }, f, indent=2, ensure_ascii=False)
    
    # Netscape格式
    txt_path = save_dir / f"cookies_curl_{ts}.txt"
    with open(txt_path, "w") as f:
        f.write("# Netscape HTTP Cookie File\n")
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.lstrip(".")
        for name, value in cookies_dict.items():
            f.write(f"{domain}\tTRUE\t/\tTRUE\t0\t{name}\t{value}\n")
    
    print(f"[+] Cookie已保存: {json_path}")
    return ts


def bypass_cloudflare_http(
    url: str,
    proxy: Optional[str] = None,
    fingerprint: str = "chrome120",
    timeout: float = 30.0,
    max_retries: int = 3,
    save_cookies: bool = True
) -> Dict[str, Any]:
    """
    使用 curl_cffi 在 HTTP/TLS 层绕过 Cloudflare 验证
    
    核心原理:
        curl_cffi 底层使用 curl-impersonate
        修改 TLS 握手中的 JA3/JA4 指纹和 HTTP/2 指纹
        使请求看起来完全像来自真实浏览器
        Cloudflare 在 TLS 层检查指纹，匹配即放行
        适用于 JS Challenge 和部分 Turnstile 场景
    
    参数:
        url: 目标网站URL
        proxy: 代理地址 (格式: http://host:port 或 socks5://host:port)
        fingerprint: 浏览器指纹类型
        timeout: 超时时间（秒）
        max_retries: 最大重试次数
        save_cookies: 是否保存Cookie到文件
    
    返回:
        {
            "success": bool,
            "cookies": dict,
            "cf_clearance": str,
            "user_agent": str,
            "error": str
        }
    """
    if not HAS_CURL_CFFI:
        return {
            "success": False,
            "cookies": {},
            "cf_clearance": None,
            "user_agent": None,
            "error": "curl_cffi 未安装，请执行: pip install curl_cffi",
            "method": "curl_cffi"
        }
    
    result = {
        "success": False,
        "cookies": {},
        "cf_clearance": None,
        "user_agent": None,
        "error": None,
        "method": "curl_cffi"
    }
    
    # 获取指纹配置
    fp_config = BROWSER_FINGERPRINTS.get(
        fingerprint, 
        BROWSER_FINGERPRINTS["chrome120"]
    )
    
    print(f"[*] 目标: {url}")
    print(f"[*] 方案: curl_cffi (TLS指纹仿冒)")
    print(f"[*] 指纹: {fp_config['name']}")
    if proxy:
        print(f"[*] 代理: {proxy}")
    
    # ------------------------------------------------------------
    # 多指纹轮换策略
    # 如果默认指纹失败，自动切换其他指纹重试
    # ------------------------------------------------------------
    retry_fingerprints = list(BROWSER_FINGERPRINTS.keys())
    # 将首选指纹放到第一位
    if fingerprint in retry_fingerprints:
        retry_fingerprints.remove(fingerprint)
    retry_fingerprints.insert(0, fingerprint)
    
    for attempt in range(max_retries):
        # 根据重试次数切换指纹
        current_fp = retry_fingerprints[attempt % len(retry_fingerprints)]
        current_fp_config = BROWSER_FINGERPRINTS.get(current_fp)
        
        if attempt > 0:
            print(f"\n[*] 第 {attempt + 1}/{max_retries} 次重试...")
            print(f"[*] 切换指纹: {current_fp_config['name']}")
            time.sleep(1)
        
        try:
            # ------------------------------------------------------------
            # 构建会话 - 核心绕过逻辑
            # impersonate 参数设置 TLS/JA3 指纹
            # curl_cffi 底层使用 curl-impersonate 修改 OpenSSL/BoringSSL
            # ------------------------------------------------------------
            import random
            user_agent = random.choice(USER_AGENTS_CHROME)
            headers = make_headers(user_agent)
            
            session = requests.Session()
            
            # 设置代理
            proxies = None
            if proxy:
                proxies = {
                    "http": proxy,
                    "https": proxy
                }
            
            # ------------------------------------------------------------
            # 第一次请求: 触发 Cloudflare JS Challenge
            # Cloudflare 返回包含内联 JavaScript 的 403 页面
            # 浏览器会自动执行该 JS 完成 PoW 计算
            # 但 curl_cffi 的 TLS 指纹已通过检测
            # 部分站点直接返回 200
            # ------------------------------------------------------------
            print(f"[*] 发送请求 (指纹: {current_fp_config['name']})...")
            
            response = session.get(
                url,
                headers=headers,
                impersonate=current_fp,
                proxies=proxies,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
            
            result["status_code"] = response.status_code
            
            # ------------------------------------------------------------
            # 分析响应状态和 Cookie
            # ------------------------------------------------------------
            # 检查是否被 Cloudflare 拦截
            page_text = response.text.lower() if response.text else ""
            
            cf_blocked = any(indicator in page_text for indicator in [
                "just a moment",
                "checking your browser",
                "verify you are human",
            ])
            
            # 提取所有 Cookie
            cookies_dict = {}
            for cookie in response.cookies:
                cookies_dict[cookie.name] = cookie.value
            
            # 从 Set-Cookie 头直接提取（更可靠）
            set_cookie = response.headers.get("Set-Cookie", "")
            
            # 提取 cf_clearance Cookie
            cf_clearance = cookies_dict.get("cf_clearance")
            if not cf_clearance and set_cookie:
                # 尝试从 Set-Cookie 头中解析
                match = re.search(r'cf_clearance=([^;]+)', set_cookie)
                if match:
                    cf_clearance = match.group(1)
                    cookies_dict["cf_clearance"] = cf_clearance
            
            result["cookies"] = cookies_dict
            result["cf_clearance"] = cf_clearance
            result["user_agent"] = user_agent
            
            if cf_clearance and not cf_blocked:
                # 成功!
                result["success"] = True
                print(f"[+] 成功获取 cf_clearance!")
                print(f"[+] 状态码: {response.status_code}")
                print(f"[+] 响应大小: {len(response.content)} bytes")
                
                if save_cookies:
                    save_cookies_to_file(cookies_dict, url, user_agent)
                break
            elif cf_clearance and cf_blocked:
                # 触发了 JS Challenge 但需要浏览器环境
                print(f"[!] TLS 指纹通过但需要浏览器环境执行 JS")
                print(f"[!] 建议切换为 bypass.py 或 bypass_nodriver.py")
                result["error"] = "需要浏览器环境执行 JS Challenge"
            else:
                # 可能被彻底拦截
                print(f"[-] 状态码: {response.status_code} | 未获取到 cf_clearance")
                if response.status_code in (403, 503):
                    print(f"[-] 被 Cloudflare 拦截 (HTTP {response.status_code})")
                
                # 检查其他 Cloudflare Cookie
                cf_cookies = [k for k in cookies_dict if k.startswith("cf_")]
                if cf_cookies:
                    print(f"[*] 检测到 Cloudflare Cookie: {cf_cookies}")
                
                result["error"] = f"HTTP {response.status_code}: 未获取到 cf_clearance"
        
        except requests.exceptions.Timeout:
            result["error"] = f"请求超时 ({timeout}秒)"
            print(f"[-] {result['error']}")
        except requests.exceptions.ConnectionError as e:
            result["error"] = f"连接错误: {e}"
            print(f"[-] {result['error']}")
        except Exception as e:
            result["error"] = str(e)
            print(f"[-] 错误: {e}")
        
        # 达到最大重试则退出
        if attempt >= max_retries - 1:
            break
    
    return result


# ============================================================
# 命令行入口
# ============================================================
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Cloudflare Turnstile 绕过工具 (curl_cffi / TLS指纹仿冒模式)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python bypass_curl_cffi.py https://example.com
  python bypass_curl_cffi.py https://example.com -p http://127.0.0.1:7890
  python bypass_curl_cffi.py https://example.com -f chrome131
  python bypass_curl_cffi.py https://example.com -n 5

可用指纹:
  chrome120, chrome124, chrome131, firefox121, safari17_0, edge101
        """
    )
    parser.add_argument("url", help="目标URL")
    parser.add_argument("-p", "--proxy", help="代理地址 (格式: http://host:port 或 socks5://host:port)")
    parser.add_argument("-f", "--fingerprint", default="chrome120",
                       choices=list(BROWSER_FINGERPRINTS.keys()),
                       help="浏览器指纹类型 (默认: chrome120)")
    parser.add_argument("-t", "--timeout", type=float, default=30.0, help="超时时间 (默认: 30秒)")
    parser.add_argument("-n", "--retries", type=int, default=3, help="最大重试次数 (默认: 3)")
    parser.add_argument("--no-save", action="store_true", help="不保存Cookie到文件")
    args = parser.parse_args()
    
    if not HAS_CURL_CFFI:
        print("[!] curl_cffi 未安装")
        print("[!] 请执行: pip install curl_cffi")
        sys.exit(1)
    
    print("\n" + "=" * 50)
    print("Cloudflare Turnstile 绕过工具 - curl_cffi 方案")
    print(f"方案: TLS/JA3 指纹仿冒")
    print("=" * 50 + "\n")
    
    # 执行绕过
    result = bypass_cloudflare_http(
        url=args.url,
        proxy=args.proxy,
        fingerprint=args.fingerprint,
        timeout=args.timeout,
        max_retries=args.retries,
        save_cookies=not args.no_save
    )
    
    # 输出结果
    print("\n" + "-" * 50)
    if result["success"]:
        print(f"[OK] 成功 | Cookie数: {len(result['cookies'])} | 状态码: {result.get('status_code')}")
        if result["cf_clearance"]:
            print(f"[OK] cf_clearance: {result['cf_clearance'][:50]}...")
    else:
        print(f"[FAIL] 失败: {result['error']}")
        
        # 给出切换建议
        print("\n[*] 提示:")
        print("[*] - 如需浏览器级别绕过: python bypass.py " + args.url)
        print("[*] - 如需 CDP 直连绕过: python bypass_nodriver.py " + args.url)
    print("-" * 50 + "\n")
