# ============================================================
# Cloudflare Turnstile 绕过工具 - nodriver 方案
# 基于 CDP 协议直连，无需 WebDriver，SeleniumBase 替代方案
# 支持 Mac / Windows / Linux
# ============================================================
# 方案说明:
#   nodriver 是 undetected-chromedriver 的官方继任者
#   通过 Chrome DevTools Protocol (CDP) 直接通信，不依赖 Selenium
#   内置 cf_verify() 方法可自动检测并点击 Cloudflare 验证
#   基于 asyncio 异步架构，性能优于 WebDriver 方案
# ============================================================

import os
import sys
import json
import time
import platform
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

try:
    import nodriver as uc
except ImportError:
    print("[!] 请安装 nodriver: pip install nodriver")
    sys.exit(1)


def is_linux() -> bool:
    """检测是否为Linux系统"""
    return platform.system().lower() == "linux"


def setup_linux_display():
    """
    设置Linux虚拟显示环境（用于无桌面环境的服务器）
    需要: xvfb, pyvirtualdisplay
    """
    if is_linux() and not os.environ.get("DISPLAY"):
        try:
            from pyvirtualdisplay import Display
            display = Display(visible=False, size=(1920, 1080))
            display.start()
            os.environ["DISPLAY"] = display.new_display_var
            print("[*] Linux: 已启动虚拟显示 (Xvfb)")
            return display
        except ImportError:
            print("[!] Linux无显示环境，请安装:")
            print("    apt-get install -y xvfb && pip install pyvirtualdisplay")
            sys.exit(1)
        except Exception as e:
            print(f"[!] 启动虚拟显示失败: {e}")
            sys.exit(1)
    return None


def load_proxies(filepath: str = "proxy.txt") -> List[str]:
    """
    从文件加载代理列表
    
    参数:
        filepath: 代理文件路径
    
    返回:
        代理列表
    """
    proxies = []
    path = Path(filepath)
    if not path.exists():
        return proxies
    
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if not line.startswith(("http://", "https://", "socks5://")):
                    line = f"http://{line}"
                proxies.append(line)
    return proxies


def save_cookies_to_file(
    cookies_list: List[Dict],
    url: str,
    user_agent: str,
    output_dir: str = "output/cookies"
) -> str:
    """
    保存Cookie到JSON和Netscape格式文件
    
    参数:
        cookies_list: Cookie列表 (nodriver格式)
        url: 目标URL
        user_agent: 浏览器UA
        output_dir: 输出目录
    
    返回:
        时间戳字符串
    """
    save_dir = Path(output_dir)
    save_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 转为字典格式
    cookies_dict = {}
    for c in cookies_list:
        cookies_dict[c.get("name", "")] = c.get("value", "")
    
    # JSON格式
    json_path = save_dir / f"cookies_nodriver_{ts}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "url": url,
            "cookies": cookies_dict,
            "user_agent": user_agent,
            "timestamp": ts,
            "method": "nodriver"
        }, f, indent=2, ensure_ascii=False)
    
    # Netscape格式 (兼容curl -b使用)
    txt_path = save_dir / f"cookies_nodriver_{ts}.txt"
    with open(txt_path, "w") as f:
        f.write("# Netscape HTTP Cookie File\n")
        for c in cookies_list:
            domain = c.get("domain", "")
            secure = "TRUE" if c.get("secure") else "FALSE"
            path = c.get("path", "/")
            expiry = int(c.get("expires", 0)) if c.get("expires") else 0
            name = c.get("name", "")
            value = c.get("value", "")
            f.write(f"{domain}\tTRUE\t{path}\t{secure}\t{expiry}\t{name}\t{value}\n")
    
    print(f"[+] Cookie已保存: {json_path}")
    return ts


async def bypass_cloudflare_nodriver(
    url: str,
    proxy: Optional[str] = None,
    headless: bool = False,
    timeout: float = 60.0,
    save_cookies: bool = True
) -> Dict[str, Any]:
    """
    使用 nodriver 绕过 Cloudflare 验证
    
    核心原理:
        nodriver 通过 CDP 协议直接控制 Chrome 浏览器
        内置的 cf_verify() 方法使用 OpenCV 图像识别
        自动定位并点击 Cloudflare 验证复选框
        绕过率高于传统 WebDriver 方案
    
    参数:
        url: 目标网站URL
        proxy: 代理地址 (格式: http://host:port)
        headless: 是否无头模式 (默认False，Cloudflare易检测无头)
        timeout: 超时时间（秒）
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
    result = {
        "success": False,
        "cookies": {},
        "cf_clearance": None,
        "user_agent": None,
        "error": None,
        "method": "nodriver"
    }
    
    browser = None
    tab = None
    
    try:
        print(f"[*] 目标: {url}")
        if proxy:
            print(f"[*] 代理: {proxy}")
        print(f"[*] 方案: nodriver (CDP直连)")
        
        # ------------------------------------------------------------
        # 启动浏览器实例
        # nodriver 通过 CDP 协议直接启动 Chrome
        # 不依赖 chromedriver，绕过了 WebDriver 检测特征
        # ------------------------------------------------------------
        browser_args = [
            "--no-first-run",
            "--disable-features=Translate",
            "--disable-blink-features=AutomationControlled",
        ]
        
        if proxy:
            browser_args.append(f"--proxy-server={proxy}")
        
        browser = await uc.start(
            headless=headless,
            browser_args=browser_args,
            lang="en-US"
        )
        
        # ------------------------------------------------------------
        # 打开目标页面
        # ------------------------------------------------------------
        tab = await browser.get(url)
        print("[*] 页面已加载，等待渲染...")
        await asyncio.sleep(3)
        
        # ------------------------------------------------------------
        # 检测 Cloudflare 验证并自动点击
        # nodriver 内置 cf_verify() 使用 OpenCV 模板匹配
        # 自动定位 Turnstile iframe 内的验证复选框
        # ------------------------------------------------------------
        page_content = await tab.get_content()
        page_text = page_content.lower()
        
        cf_indicators = [
            "turnstile",
            "challenges.cloudflare",
            "just a moment",
            "verify you are human",
            "checking your browser"
        ]
        
        if any(indicator in page_text for indicator in cf_indicators):
            print("[*] 检测到 Cloudflare 验证页面")
            
            try:
                # 使用 nodriver 内置的 cf_verify() 方法
                # 该方法通过 OpenCV 图像识别自动点击验证复选框
                await tab.cf_verify()
                print("[+] cf_verify() 执行完成")
                
                # 等待验证通过后的页面跳转
                await asyncio.sleep(5)
                
            except Exception as e:
                print(f"[!] cf_verify() 执行异常: {e}")
                # 备用方案: 手动查找并点击
                try:
                    await tab.find("verify you are human")
                    print("[*] 备用: 尝试手动交互...")
                    await asyncio.sleep(5)
                except Exception:
                    pass
        
        # ------------------------------------------------------------
        # 提取 Cookie 信息
        # nodriver 使用 send() 发送 CDP 命令获取 Cookie
        # ------------------------------------------------------------
        cookies_raw = await tab.send(
            uc.cdp.network.get_cookies()
        )
        
        cookies_list = cookies_raw.get("cookies", [])
        result["cookies"] = {
            c.get("name", ""): c.get("value", "")
            for c in cookies_list
        }
        result["cf_clearance"] = result["cookies"].get("cf_clearance")
        
        # 获取 User-Agent
        try:
            ua_result = await tab.send(
                uc.cdp.runtime.evaluate(expression="navigator.userAgent")
            )
            result["user_agent"] = ua_result.get("result", {}).get("value", "")
        except Exception:
            result["user_agent"] = "unknown"
        
        if result["cf_clearance"]:
            result["success"] = True
            print(f"[+] 成功获取 cf_clearance!")
            print(f"[+] User-Agent: {result['user_agent'][:80]}...")
            
            # 保存Cookie
            if save_cookies:
                save_cookies_to_file(
                    cookies_list,
                    url,
                    result["user_agent"]
                )
        else:
            result["error"] = "未获取到 cf_clearance"
            print(f"[-] {result['error']}")
            print(f"[-] 获取到的Cookie: {list(result['cookies'].keys())}")
    
    except asyncio.TimeoutError:
        result["error"] = f"操作超时 ({timeout}秒)"
        print(f"[-] {result['error']}")
    except Exception as e:
        result["error"] = str(e)
        print(f"[-] 错误: {e}")
    finally:
        # 清理浏览器资源
        if browser:
            try:
                browser.stop()
                print("[*] 浏览器已关闭")
            except Exception:
                pass
    
    return result


def bypass_sync(
    url: str,
    proxy: Optional[str] = None,
    headless: bool = False,
    timeout: float = 60.0,
    save_cookies: bool = True
) -> Dict[str, Any]:
    """
    同步包装器，方便在非异步环境中调用
    
    参数:
        url: 目标网站URL
        proxy: 代理地址
        headless: 是否无头模式
        timeout: 超时时间（秒）
        save_cookies: 是否保存Cookie
    
    返回:
        与 bypass_cloudflare_nodriver 相同格式的结果字典
    """
    return asyncio.run(
        bypass_cloudflare_nodriver(
            url=url,
            proxy=proxy,
            headless=headless,
            timeout=timeout,
            save_cookies=save_cookies
        )
    )


# ============================================================
# 命令行入口
# ============================================================
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Cloudflare Turnstile 绕过工具 (nodriver / CDP直连模式)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python bypass_nodriver.py https://example.com
  python bypass_nodriver.py https://example.com -p http://127.0.0.1:7890
  python bypass_nodriver.py https://example.com --headless
        """
    )
    parser.add_argument("url", help="目标URL")
    parser.add_argument("-p", "--proxy", help="代理地址 (格式: http://host:port)")
    parser.add_argument("--headless", action="store_true", help="启用无头模式 (不推荐，Cloudflare可检测)")
    parser.add_argument("-t", "--timeout", type=float, default=60.0, help="超时时间 (默认: 60秒)")
    parser.add_argument("--no-save", action="store_true", help="不保存Cookie到文件")
    args = parser.parse_args()
    
    # Linux虚拟显示
    display = setup_linux_display()
    
    print("\n" + "=" * 50)
    print("Cloudflare Turnstile 绕过工具 - nodriver 方案")
    print(f"系统: {platform.system()} {platform.release()}")
    print(f"方案: CDP 直连 (nodriver)")
    print("=" * 50 + "\n")
    
    # 执行绕过
    result = asyncio.run(
        bypass_cloudflare_nodriver(
            url=args.url,
            proxy=args.proxy,
            headless=args.headless,
            timeout=args.timeout,
            save_cookies=not args.no_save
        )
    )
    
    # 输出结果
    print("\n" + "-" * 50)
    if result["success"]:
        print(f"[OK] 成功 | Cookie数: {len(result['cookies'])}")
        if result["cf_clearance"]:
            print(f"[OK] cf_clearance: {result['cf_clearance'][:50]}...")
    else:
        print(f"[FAIL] 失败: {result['error']}")
    print("-" * 50 + "\n")
    
    # 清理
    if display:
        display.stop()
