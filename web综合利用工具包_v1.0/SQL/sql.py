import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import threading
import os
import time
import json
from datetime import datetime
import re
import shutil
from pathlib import Path

class SQLmapGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SQLmap 图形化漏洞利用工具1.0")
        self.root.geometry("1000x700")
        self.root.configure(bg="#f0f0f0")
        
        # 确保输出目录存在
        self.output_dir = os.path.join(os.getcwd(), "sqlmap_results")
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        self.create_widgets()
        
    def create_widgets(self):
        # 创建标签页
        tab_control = ttk.Notebook(self.root)
        
        # 主功能标签页
        main_tab = ttk.Frame(tab_control)
        # WAF绕过标签页
        waf_tab = ttk.Frame(tab_control)
        # 结果标签页
        results_tab = ttk.Frame(tab_control)
        
        tab_control.add(main_tab, text="主功能")
        tab_control.add(waf_tab, text="WAF绕过")
        tab_control.add(results_tab, text="扫描结果")
        
        tab_control.pack(expand=1, fill="both")
        
        # 主功能界面
        self.create_main_tab(main_tab)
        # WAF绕过界面
        self.create_waf_tab(waf_tab)
        # 结果界面
        self.create_results_tab(results_tab)
        
        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_main_tab(self, parent):
        # 目标URL区域
        url_frame = ttk.LabelFrame(parent, text="目标设置")
        url_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(url_frame, text="目标URL:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.url_entry = ttk.Entry(url_frame)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        url_frame.columnconfigure(1, weight=1)
        
        # 请求方法选择
        method_frame = ttk.Frame(url_frame)
        method_frame.grid(row=0, column=2, padx=5, pady=5)
        
        self.method_var = tk.StringVar(value="GET")
        ttk.Radiobutton(method_frame, text="GET", variable=self.method_var, value="GET").pack(side=tk.LEFT)
        ttk.Radiobutton(method_frame, text="POST", variable=self.method_var, value="POST").pack(side=tk.LEFT)
        
        # POST参数区域
        self.post_frame = ttk.LabelFrame(parent, text="POST参数 (当方法为POST时)")
        self.post_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(self.post_frame, text="参数:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.post_entry = ttk.Entry(self.post_frame)
        self.post_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.post_frame.columnconfigure(1, weight=1)
        
        # 参数预设按钮
        self.param_presets = ["id=1", "user=admin&pass=123", "page=home&item=1", "search=test"]
        preset_btn = ttk.Button(self.post_frame, text="预设参数", command=self.show_param_presets)
        preset_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # 扫描选项区域
        options_frame = ttk.LabelFrame(parent, text="扫描选项")
        options_frame.pack(fill="x", padx=10, pady=5)
        
        # 线程数
        ttk.Label(options_frame, text="线程数:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.threads_var = tk.StringVar(value="1")
        ttk.Combobox(options_frame, textvariable=self.threads_var, values=["1", "2", "5", "10"], width=5).grid(row=0, column=1, padx=5, pady=5)
        
        # 扫描级别
        ttk.Label(options_frame, text="扫描级别:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.level_var = tk.StringVar(value="1")
        ttk.Combobox(options_frame, textvariable=self.level_var, values=["1", "2", "3", "4", "5"], width=5).grid(row=0, column=3, padx=5, pady=5)
        
        # 风险级别
        ttk.Label(options_frame, text="风险级别:").grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        self.risk_var = tk.StringVar(value="1")
        ttk.Combobox(options_frame, textvariable=self.risk_var, values=["1", "2", "3"], width=5).grid(row=0, column=5, padx=5, pady=5)
        
        # 输出区域
        output_frame = ttk.LabelFrame(parent, text="输出")
        output_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD)
        self.output_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.output_text.config(state=tk.DISABLED)
        
        # 按钮区域
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill="x", padx=10, pady=5)
        
        self.start_btn = ttk.Button(btn_frame, text="开始扫描", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="停止扫描", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(btn_frame, text="清空输出", command=self.clear_output)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.generate_report_btn = ttk.Button(btn_frame, text="生成报告", command=self.generate_report, state=tk.DISABLED)
        self.generate_report_btn.pack(side=tk.RIGHT, padx=5)
        
        # 绑定方法选择变化事件
        self.method_var.trace_add("write", self.on_method_change)
        self.on_method_change()  # 初始化状态
    
    def create_waf_tab(self, parent):
        # WAF绕过选项
        waf_frame = ttk.LabelFrame(parent, text="WAF绕过设置")
        waf_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # 随机User-Agent
        self.random_agent_var = tk.BooleanVar()
        ttk.Checkbutton(waf_frame, text="使用随机User-Agent", variable=self.random_agent_var).grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        
        # 延迟请求
        ttk.Label(waf_frame, text="请求延迟(秒):").grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        self.delay_var = tk.StringVar(value="0")
        ttk.Entry(waf_frame, textvariable=self.delay_var, width=10).grid(row=0, column=2, padx=5, pady=5)
        
        # 超时时间
        ttk.Label(waf_frame, text="超时时间(秒):").grid(row=0, column=3, padx=10, pady=5, sticky=tk.W)
        self.timeout_var = tk.StringVar(value="30")
        ttk.Entry(waf_frame, textvariable=self.timeout_var, width=10).grid(row=0, column=4, padx=5, pady=5)
        
        # 重试次数
        ttk.Label(waf_frame, text="重试次数:").grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        self.retries_var = tk.StringVar(value="3")
        ttk.Entry(waf_frame, textvariable=self.retries_var, width=10).grid(row=1, column=1, padx=5, pady=5)
        
        # 伪造Referer
        ttk.Label(waf_frame, text="Referer:").grid(row=1, column=2, padx=10, pady=5, sticky=tk.W)
        self.referer_var = tk.StringVar()
        ttk.Entry(waf_frame, textvariable=self.referer_var).grid(row=1, column=3, padx=5, pady=5, columnspan=2, sticky=tk.EW)
        waf_frame.columnconfigure(3, weight=1)
        
        # 伪造X-Forwarded-For
        ttk.Label(waf_frame, text="X-Forwarded-For:").grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        self.xff_var = tk.StringVar()
        ttk.Entry(waf_frame, textvariable=self.xff_var).grid(row=2, column=1, padx=5, pady=5, columnspan=4, sticky=tk.EW)
        
        # tamper脚本
        ttk.Label(waf_frame, text="Tamper脚本:").grid(row=3, column=0, padx=10, pady=5, sticky=tk.NW)
        
        # 常见的tamper脚本
        tamper_scripts = [
            "apostrophemask", "apostrophenullencode", "appendnullbyte",
            "base64encode", "between", "bluecoat", "chardoubleencode",
            "charencode", "charunicodeencode", "commalesslimit",
            "commalessmid", "convertmemo", "equaltolike", "escapequotes",
            "greatest", "halfversionedmorekeywords", "htmlencode",
            "ifnull2ifisnull", "informationschemacomment", "lowercase",
            "modsecurityversioned", "modsecurityzeroversioned", "multiplespaces",
            "nonrecursivereplacement", "overlongutf8", "overlongutf8more",
            "percentage", "plus2concat", "plus2fnconcat", "randomcase",
            "randomcomments", "securesphere", "sp_password", "space2comment",
            "space2dash", "space2hash", "space2morecomment", "space2morehash",
            "space2mssqlblank", "space2mssqlhash", "space2mysqlblank",
            "space2mysqldash", "space2plus", "space2randomblank", "symboliclogical",
            "unionalltounion", "unmagicquotes", "uppercase", "varnish",
            "versionedkeywords", "versionedmorekeywords", "xforwardedfor"
        ]
        
        self.tamper_listbox = tk.Listbox(waf_frame, selectmode=tk.MULTIPLE, height=10, width=30)
        for script in tamper_scripts:
            self.tamper_listbox.insert(tk.END, script)
        self.tamper_listbox.grid(row=3, column=1, padx=5, pady=5, sticky=tk.NW)
        
        # 滚动条
        tamper_scrollbar = ttk.Scrollbar(waf_frame, orient=tk.VERTICAL, command=self.tamper_listbox.yview)
        tamper_scrollbar.grid(row=3, column=2, sticky=tk.NS)
        self.tamper_listbox.config(yscrollcommand=tamper_scrollbar.set)
        
        # 按钮
        tamper_btn_frame = ttk.Frame(waf_frame)
        tamper_btn_frame.grid(row=3, column=3, padx=5, pady=5, sticky=tk.N)
        
        ttk.Button(tamper_btn_frame, text="全选", command=lambda: self.select_all_tamper(True)).pack(fill=tk.X, pady=2)
        ttk.Button(tamper_btn_frame, text="全不选", command=lambda: self.select_all_tamper(False)).pack(fill=tk.X, pady=2)
        ttk.Button(tamper_btn_frame, text="常用组合", command=self.common_tamper_combination).pack(fill=tk.X, pady=2)
        
        # WAF绕过帮助信息
        help_text = """
WAF绕过技巧:
1. 使用随机User-Agent可以绕过基于User-Agent的检测
2. 添加适当延迟可以绕过速率限制
3. 伪造Referer和X-Forwarded-For可以绕过某些来源检测
4. Tamper脚本可以对payload进行变形处理，绕过特征检测
5. 对于Cloudflare等CDN/WAF，可以尝试使用--cf-break选项

常用Tamper组合:
- 通用: apostrophemask, space2comment, randomcase
- MySQL: between, bluecoat, space2dash
- SQL Server: versionedkeywords, space2mssqlhash
- Oracle: lowercase, greatest, space2plus
        """
        help_label = ttk.Label(waf_frame, text=help_text, justify=tk.LEFT, wraplength=500)
        help_label.grid(row=3, column=4, padx=10, pady=5, sticky=tk.NW)
    
    def create_results_tab(self, parent):
        # 结果列表
        results_frame = ttk.LabelFrame(parent, text="扫描历史")
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.results_tree = ttk.Treeview(results_frame, columns=("时间", "目标", "状态", "结果文件"), show="headings")
        self.results_tree.heading("时间", text="时间")
        self.results_tree.heading("目标", text="目标")
        self.results_tree.heading("状态", text="状态")
        self.results_tree.heading("结果文件", text="结果文件")
        
        self.results_tree.column("时间", width=150)
        self.results_tree.column("目标", width=300)
        self.results_tree.column("状态", width=100)
        self.results_tree.column("结果文件", width=250)
        
        self.results_tree.pack(side=tk.LEFT, fill="both", expand=True, padx=5, pady=5)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_tree.config(yscrollcommand=scrollbar.set)
        
        # 结果操作按钮
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(btn_frame, text="查看结果", command=self.view_result).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="删除结果", command=self.delete_result).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="导出报告", command=self.export_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="刷新列表", command=self.refresh_results).pack(side=tk.RIGHT, padx=5)
        
        # 初始刷新结果列表
        self.refresh_results()
    
    def on_method_change(self, *args):
        # 根据请求方法显示或隐藏POST参数区域
        if self.method_var.get() == "POST":
            self.post_frame.pack(fill="x", padx=10, pady=5)
        else:
            self.post_frame.pack_forget()
    
    def show_param_presets(self):
        # 创建参数预设对话框
        preset_window = tk.Toplevel(self.root)
        preset_window.title("选择预设参数")
        preset_window.geometry("400x300")
        preset_window.transient(self.root)
        preset_window.grab_set()
        
        listbox = tk.Listbox(preset_window)
        listbox.pack(fill="both", expand=True, padx=10, pady=10)
        
        for param in self.param_presets:
            listbox.insert(tk.END, param)
        
        def select_param():
            if listbox.curselection():
                selected = listbox.get(listbox.curselection())
                self.post_entry.delete(0, tk.END)
                self.post_entry.insert(0, selected)
                preset_window.destroy()
        
        ttk.Button(preset_window, text="选择", command=select_param).pack(pady=10)
    
    def select_all_tamper(self, select):
        # 全选或全不选tamper脚本
        self.tamper_listbox.selection_clear(0, tk.END)
        if select:
            self.tamper_listbox.selection_set(0, tk.END)
    
    def common_tamper_combination(self):
        # 常用的tamper组合
        common_combos = [
            ("通用组合", ["apostrophemask", "space2comment", "randomcase"]),
            ("MySQL组合", ["between", "bluecoat", "space2dash"]),
            ("SQL Server组合", ["versionedkeywords", "space2mssqlhash"]),
            ("Oracle组合", ["lowercase", "greatest", "space2plus"])
        ]
        
        combo_window = tk.Toplevel(self.root)
        combo_window.title("选择常用组合")
        combo_window.geometry("300x200")
        combo_window.transient(self.root)
        combo_window.grab_set()
        
        listbox = tk.Listbox(combo_window)
        listbox.pack(fill="both", expand=True, padx=10, pady=10)
        
        for name, _ in common_combos:
            listbox.insert(tk.END, name)
        
        def select_combo():
            if listbox.curselection():
                index = listbox.curselection()[0]
                _, scripts = common_combos[index]
                
                self.tamper_listbox.selection_clear(0, tk.END)
                for i in range(self.tamper_listbox.size()):
                    if self.tamper_listbox.get(i) in scripts:
                        self.tamper_listbox.selection_set(i)
                
                combo_window.destroy()
        
        ttk.Button(combo_window, text="选择", command=select_combo).pack(pady=10)
    
    def append_output(self, text):
        # 在输出区域添加文本
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, text + "\n")
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
    
    def clear_output(self):
        # 清空输出区域
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
    
    def start_scan(self):
        # 检查URL是否为空
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("错误", "请输入目标URL")
            return
        
        # 禁用开始按钮，启用停止按钮
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.generate_report_btn.config(state=tk.DISABLED)
        self.status_var.set("正在扫描...")
        
        # 生成唯一的结果目录
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_result_dir = os.path.join(self.output_dir, f"scan_{timestamp}")
        os.makedirs(self.current_result_dir, exist_ok=True)
        
        # 保存当前扫描信息
        self.current_scan_info = {
            "时间": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "目标": url,
            "状态": "进行中",
            "结果文件": os.path.basename(self.current_result_dir)
        }
        
        # 启动扫描线程
        self.scan_process = None
        self.scan_thread = threading.Thread(target=self.run_scan, args=(url, self.current_result_dir))
        self.scan_thread.start()
    
    def run_scan(self, url, result_dir):
        try:
            # 构建sqlmap命令
            cmd = ["sqlmap", "-u", url, "--output-dir", result_dir, "-v", "1"]
            
            # 添加方法和参数
            method = self.method_var.get()
            if method == "POST":
                post_data = self.post_entry.get().strip()
                if post_data:
                    cmd.extend(["--data", post_data])
            
            # 添加线程数
            cmd.extend(["--threads", self.threads_var.get()])
            
            # 添加扫描级别和风险级别
            cmd.extend(["--level", self.level_var.get()])
            cmd.extend(["--risk", self.risk_var.get()])
            
            # 添加WAF绕过选项
            if self.random_agent_var.get():
                cmd.append("--random-agent")
            
            delay = self.delay_var.get().strip()
            if delay and delay.isdigit() and int(delay) > 0:
                cmd.extend(["--delay", delay])
            
            timeout = self.timeout_var.get().strip()
            if timeout and timeout.isdigit() and int(timeout) > 0:
                cmd.extend(["--timeout", timeout])
            
            retries = self.retries_var.get().strip()
            if retries and retries.isdigit() and int(retries) > 0:
                cmd.extend(["--retries", retries])
            
            referer = self.referer_var.get().strip()
            if referer:
                cmd.extend(["--referer", referer])
            
            xff = self.xff_var.get().strip()
            if xff:
                cmd.extend(["--headers", f"X-Forwarded-For: {xff}"])
            
            # 添加tamper脚本
            selected_tamper = [self.tamper_listbox.get(i) for i in self.tamper_listbox.curselection()]
            if selected_tamper:
                cmd.extend(["--tamper", ",".join(selected_tamper)])
            
            # 添加报告选项
            cmd.extend(["--batch", "--json-output"])
            
            self.append_output(f"执行命令: {' '.join(cmd)}")
            
            # 执行sqlmap命令
            self.scan_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # 实时输出结果
            for line in self.scan_process.stdout:
                self.append_output(line.strip())
            
            # 等待进程结束
            self.scan_process.wait()
            
            # 检查扫描结果
            if self.scan_process.returncode == 0:
                self.current_scan_info["状态"] = "完成"
                self.append_output("扫描完成")
                self.generate_report_btn.config(state=tk.NORMAL)
            else:
                self.current_scan_info["状态"] = "失败"
                self.append_output(f"扫描失败，返回代码: {self.scan_process.returncode}")
        
        except Exception as e:
            self.append_output(f"扫描出错: {str(e)}")
            self.current_scan_info["状态"] = "错误"
        
        finally:
            # 更新状态和按钮
            self.status_var.set("就绪")
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            
            # 保存扫描信息
            self.save_scan_info(self.current_scan_info, result_dir)
            
            # 刷新结果列表
            self.refresh_results()
    
    def stop_scan(self):
        if self.scan_process and self.scan_process.poll() is None:
            self.scan_process.terminate()
            self.append_output("扫描已停止")
            self.current_scan_info["状态"] = "已停止"
            self.save_scan_info(self.current_scan_info, self.current_result_dir)
    
    def save_scan_info(self, info, result_dir):
        # 保存扫描信息到文件
        info_file = os.path.join(result_dir, "scan_info.json")
        with open(info_file, "w", encoding="utf-8") as f:
            json.dump(info, f, ensure_ascii=False, indent=2)
    
    def refresh_results(self):
        # 清空现有列表
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # 加载所有扫描结果
        if os.path.exists(self.output_dir):
            for dir_name in os.listdir(self.output_dir):
                dir_path = os.path.join(self.output_dir, dir_name)
                if os.path.isdir(dir_path):
                    info_file = os.path.join(dir_path, "scan_info.json")
                    if os.path.exists(info_file):
                        with open(info_file, "r", encoding="utf-8") as f:
                            try:
                                info = json.load(f)
                                self.results_tree.insert("", tk.END, values=(
                                    info.get("时间", ""),
                                    info.get("目标", ""),
                                    info.get("状态", ""),
                                    info.get("结果文件", "")
                                ))
                            except:
                                pass
    
    def view_result(self):
        # 查看选中的结果
        selected = self.results_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请选择一个结果")
            return
        
        item = selected[0]
        result_file = self.results_tree.item(item, "values")[3]
        result_dir = os.path.join(self.output_dir, result_file)
        
        if not os.path.exists(result_dir):
            messagebox.showerror("错误", "结果文件不存在")
            return
        
        # 查找JSON报告
        json_report = None
        for file in os.listdir(result_dir):
            if file.endswith(".json"):
                json_report = os.path.join(result_dir, file)
                break
        
        # 显示结果
        result_window = tk.Toplevel(self.root)
        result_window.title(f"扫描结果: {result_file}")
        result_window.geometry("800x600")
        
        if json_report and os.path.exists(json_report):
            with open(json_report, "r", encoding="utf-8") as f:
                content = f.read()
            
            text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
            text.pack(fill="both", expand=True, padx=10, pady=10)
            text.insert(tk.END, content)
            text.config(state=tk.DISABLED)
        else:
            ttk.Label(result_window, text="未找到结果报告", font=("Arial", 12)).pack(pady=20)
    
    def delete_result(self):
        # 删除选中的结果
        selected = self.results_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请选择一个结果")
            return
        
        item = selected[0]
        result_file = self.results_tree.item(item, "values")[3]
        result_dir = os.path.join(self.output_dir, result_file)
        
        if messagebox.askyesno("确认", f"确定要删除 {result_file} 吗?"):
            try:
                if os.path.exists(result_dir):
                    shutil.rmtree(result_dir)
                self.refresh_results()
                messagebox.showinfo("提示", "删除成功")
            except Exception as e:
                messagebox.showerror("错误", f"删除失败: {str(e)}")
    
    def generate_report(self):
        # 生成漏洞报告
        if not hasattr(self, 'current_result_dir') or not os.path.exists(self.current_result_dir):
            messagebox.showerror("错误", "没有可生成报告的扫描结果")
            return
        
        # 查找JSON报告
        json_report = None
        for file in os.listdir(self.current_result_dir):
            if file.endswith(".json"):
                json_report = os.path.join(self.current_result_dir, file)
                break
        
        if not json_report or not os.path.exists(json_report):
            messagebox.showerror("错误", "未找到扫描结果数据")
            return
        
        # 解析JSON报告
        try:
            with open(json_report, "r", encoding="utf-8") as f:
                scan_data = json.load(f)
            
            # 生成HTML报告
            report_path = os.path.join(self.current_result_dir, "vulnerability_report.html")
            self.create_html_report(scan_data, report_path)
            
            messagebox.showinfo("成功", f"漏洞报告已生成: {report_path}")
            
            # 提供下载选项
            if messagebox.askyesno("下载报告", "是否要将报告保存到其他位置?"):
                save_path = filedialog.asksaveasfilename(
                    defaultextension=".html",
                    filetypes=[("HTML文件", "*.html"), ("所有文件", "*.*")],
                    initialfile="vulnerability_report.html"
                )
                if save_path:
                    shutil.copy2(report_path, save_path)
                    messagebox.showinfo("成功", f"报告已保存到: {save_path}")
        
        except Exception as e:
            messagebox.showerror("错误", f"生成报告失败: {str(e)}")
    
    def create_html_report(self, scan_data, output_path):
        # 创建HTML格式的漏洞报告
        html = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>SQL注入漏洞扫描报告</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }
        h1, h2, h3 { color: #2c3e50; }
        .header { border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }
        .info-section { margin-bottom: 30px; }
        .vulnerability { background-color: #f8f9fa; border-left: 4px solid #e74c3c; padding: 15px; margin: 10px 0; }
        .parameter { font-family: monospace; background-color: #ecf0f1; padding: 2px 5px; }
        .payload { font-family: monospace; color: #c0392b; }
        .summary { background-color: #e8f4f8; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SQL注入漏洞扫描报告</h1>
        <p>生成时间: {generate_time}</p>
    </div>
    
    <div class="info-section">
        <h2>目标信息</h2>
        <p><strong>URL:</strong> {target_url}</p>
        <p><strong>方法:</strong> {method}</p>
        {post_data}
        <p><strong>扫描时间:</strong> {scan_time}</p>
    </div>
    
    <div class="summary">
        <h2>扫描摘要</h2>
        <p><strong>发现的漏洞数量:</strong> {vuln_count}</p>
        <p><strong>数据库类型:</strong> {dbms}</p>
    </div>
    
    {vulnerabilities}
    
    <div class="info-section">
        <h2>修复建议</h2>
        <ul>
            <li>使用参数化查询或预编译语句</li>
            <li>对用户输入进行严格的验证和过滤</li>
            <li>最小权限原则配置数据库账户</li>
            <li>定期更新和修补数据库系统</li>
            <li>部署Web应用防火墙(WAF)增强防护</li>
        </ul>
    </div>
</body>
</html>
        """
        
        # 提取报告数据
        generate_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target_url = scan_data.get("target", {}).get("url", "未知")
        method = scan_data.get("target", {}).get("method", "GET")
        
        post_data = ""
        if method == "POST":
            data = scan_data.get("target", {}).get("data", "")
            post_data = f"<p><strong>POST参数:</strong> {data}</p>"
        
        scan_start = scan_data.get("time", {}).get("start", "未知")
        scan_end = scan_data.get("time", {}).get("end", "未知")
        scan_time = f"{scan_start} 至 {scan_end}"
        
        dbms = scan_data.get("dbms", "未知")
        
        # 提取漏洞信息
        vulnerabilities = []
        for payload in scan_data.get("payloads", []):
            if payload.get("vulnerable", False):
                vuln_info = f"""
        <div class="vulnerability">
            <h3>漏洞 #{len(vulnerabilities)+1}</h3>
            <p><strong>参数:</strong> <span class="parameter">{payload.get('parameter', '未知')}</span></p>
            <p><strong>类型:</strong> {payload.get('type', '未知')}</p>
            <p><strong> payload:</strong> <span class="payload">{payload.get('payload', '未知')}</span></p>
            <p><strong>确认方法:</strong> {payload.get('title', '未知')}</p>
        </div>
                """
                vulnerabilities.append(vuln_info)
        
        vuln_count = len(vulnerabilities)
        vulnerabilities_html = "\n".join(vulnerabilities) if vulnerabilities else "<p>未发现SQL注入漏洞</p>"
        
        # 填充HTML模板
        html = html.format(
            generate_time=generate_time,
            target_url=target_url,
            method=method,
            post_data=post_data,
            scan_time=scan_time,
            vuln_count=vuln_count,
            dbms=dbms,
            vulnerabilities=vulnerabilities_html
        )
        
        # 保存HTML报告
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
    
    def export_report(self):
        # 导出选中的报告
        selected = self.results_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请选择一个结果")
            return
        
        item = selected[0]
        result_file = self.results_tree.item(item, "values")[3]
        result_dir = os.path.join(self.output_dir, result_file)
        
        # 查找HTML报告
        html_report = os.path.join(result_dir, "vulnerability_report.html")
        if not os.path.exists(html_report):
            # 如果没有HTML报告，尝试生成
            json_report = None
            for file in os.listdir(result_dir):
                if file.endswith(".json"):
                    json_report = os.path.join(result_dir, file)
                    break
            
            if not json_report or not os.path.exists(json_report):
                messagebox.showerror("错误", "未找到扫描结果数据")
                return
            
            # 解析JSON并生成HTML报告
            try:
                with open(json_report, "r", encoding="utf-8") as f:
                    scan_data = json.load(f)
                self.create_html_report(scan_data, html_report)
            except Exception as e:
                messagebox.showerror("错误", f"生成报告失败: {str(e)}")
                return
        
        # 保存报告到指定位置
        save_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML文件", "*.html"), ("所有文件", "*.*")],
            initialfile="vulnerability_report.html"
        )
        
        if save_path:
            try:
                shutil.copy2(html_report, save_path)
                messagebox.showinfo("成功", f"报告已导出到: {save_path}")
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SQLmapGUI(root)
    root.mainloop()
