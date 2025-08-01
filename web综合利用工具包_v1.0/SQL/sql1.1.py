import os
import tkinter as tk
import re
import json
import datetime
import tkinter.messagebox as msgbox
from tkinter import ttk, Text, filedialog


# 尝试导入必要的库
try:
    import requests
except ImportError:
    os.system("pip install requests")
    try:
        import requests
    except ImportError:
        msgbox.showerror("安装错误", "无法安装requests库，请手动安装后重试")


# SQLmap核心功能实现（集成版，不调用外部程序）
class SQLmapCore:
    def __init__(self):
        # 模拟数据库结构，实际使用时可替换为真实的SQL注入检测逻辑
        self.databases = []
        self.tables = {}
        self.columns = {}
        self.data = {}
        self.current_results = {}
        
    def detect_databases(self, url, options):
        """检测数据库"""
        # 这里是模拟逻辑，实际应用中应替换为真实的SQL注入检测代码
        self.databases = ["information_schema", "mysql", "performance_schema", "sys", "webappdb"]
        self.current_results['databases'] = self.databases
        return self.databases
    
    def detect_tables(self, database, url, options):
        """检测指定数据库中的表"""
        # 模拟数据
        table_data = {
            "information_schema": ["COLUMNS", "KEY_COLUMN_USAGE", "SCHEMATA", "TABLES"],
            "mysql": ["user", "db", "tables_priv", "columns_priv"],
            "webappdb": ["users", "products", "orders", "comments"]
        }
        self.tables[database] = table_data.get(database, [])
        self.current_results['tables'] = self.tables[database]
        return self.tables[database]
    
    def detect_columns(self, database, table, url, options):
        """检测指定表中的列"""
        # 模拟数据
        column_data = {
            ("webappdb", "users"): ["id", "username", "password", "email", "role", "created_at"],
            ("webappdb", "products"): ["id", "name", "price", "stock", "category"],
            ("mysql", "user"): ["Host", "User", "Password", "Select_priv", "Insert_priv"]
        }
        key = (database, table)
        self.columns[key] = column_data.get(key, [])
        self.current_results['columns'] = self.columns[key]
        return self.columns[key]
    
    def fetch_data(self, database, table, columns, url, options):
        """获取指定列的数据"""
        # 模拟数据
        data_samples = {
            ("webappdb", "users", ["username", "password"]): [
                ("admin", "SecurePass123!"),
                ("user1", "user123"),
                ("moderator", "mod456"),
                ("guest", "guest789")
            ],
            ("webappdb", "products", ["name", "price"]): [
                ("Laptop", "999.99"),
                ("Smartphone", "699.99"),
                ("Tablet", "299.99")
            ]
        }
        
        key = (database, table, tuple(columns))
        self.data[key] = data_samples.get(key, [])
        self.current_results['data'] = self.data[key]
        return self.data[key]
    
    def run(self, options):
        """执行SQLmap命令"""
        url = options.get('url', '')
        result = {
            'success': True,
            'message': [],
            'data': {}
        }
        
        # 处理不同的命令选项
        if options.get('dbs'):
            dbs = self.detect_databases(url, options)
            result['message'].append(f"发现 {len(dbs)} 个数据库")
            result['data']['databases'] = dbs
            
        if options.get('tables') and options.get('D'):
            tables = self.detect_tables(options['D'], url, options)
            result['message'].append(f"在数据库 {options['D']} 中发现 {len(tables)} 个表")
            result['data']['tables'] = tables
            
        if options.get('columns') and options.get('D') and options.get('T'):
            columns = self.detect_columns(options['D'], options['T'], url, options)
            result['message'].append(f"在表 {options['D']}.{options['T']} 中发现 {len(columns)} 个列")
            result['data']['columns'] = columns
            
        if options.get('dump') and options.get('D') and options.get('T') and options.get('C'):
            columns_list = options['C'].split(',')
            data = self.fetch_data(options['D'], options['T'], columns_list, url, options)
            result['message'].append(f"从 {options['D']}.{options['T']} 提取了 {len(data)} 条记录")
            result['data']['data'] = data
            
        return result


# 主应用类
class SQLmapGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SQLmap 集成GUI版")
        self.root.geometry("1200x700")
        
        # 初始化SQLmap核心
        self.sqlmap_core = SQLmapCore()
        
        # 创建变量
        self.create_variables()
        
        # 创建UI
        self.create_widgets()
        
        # 绑定事件
        self.bind_events()
    
    def create_variables(self):
        """创建界面变量"""
        # 基本选项
        self.level_var = tk.StringVar(value='1')
        self.risk_var = tk.StringVar(value='1')
        self.threads_var = tk.StringVar(value='10')
        
        # 检测选项
        self.current_db_var = tk.BooleanVar()
        self.current_user_var = tk.BooleanVar()
        self.is_dba_var = tk.BooleanVar()
        self.dbs_var = tk.BooleanVar()
        self.tables_var = tk.BooleanVar()
        self.columns_var = tk.BooleanVar()
        self.dump_var = tk.BooleanVar()
        self.dump_all_var = tk.BooleanVar()
        
        # 目标和注入选项
        self.target_url_var = tk.StringVar()
        self.injection_type_var = tk.StringVar(value="GET")
        self.referer_var = tk.StringVar()
        self.cookie_var = tk.StringVar()
        
        # 数据库对象选择
        self.db_var = tk.StringVar()
        self.table_var = tk.StringVar()
        self.column_var = tk.StringVar()
        
        # 其他选项
        self.proxy_var = tk.StringVar()
        self.batch_var = tk.BooleanVar(value=True)
        self.technique_var = tk.StringVar(value="全选")
        self.dbms_type_var = tk.StringVar()
        
        # WAF绕过选项
        self.waf_bypass = {
            "random_agent": tk.BooleanVar(),
            "tamper": tk.BooleanVar(),
            "chunked": tk.BooleanVar(),
            "delay": tk.BooleanVar(),
            "headers": tk.BooleanVar(),
            "skip_urlencode": tk.BooleanVar(),
            "base64": tk.BooleanVar(),
            "space2comment": tk.BooleanVar(),
            "charencode": tk.BooleanVar(),
            "unmagicquotes": tk.BooleanVar()
        }
    
    def create_widgets(self):
        """创建界面组件"""
        # 主面板
        main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 左侧面板 - 选项设置
        left_frame = ttk.LabelFrame(main_paned, text="选项设置")
        main_paned.add(left_frame, weight=1)
        
        # 中间面板 - 目标和输出
        middle_frame = ttk.LabelFrame(main_paned, text="目标和结果")
        main_paned.add(middle_frame, weight=2)
        
        # 右侧面板 - 数据浏览
        right_frame = ttk.LabelFrame(main_paned, text="数据浏览")
        main_paned.add(right_frame, weight=1)
        
        # 构建左侧面板
        self.build_left_panel(left_frame)
        
        # 构建中间面板
        self.build_middle_panel(middle_frame)
        
        # 构建右侧面板
        self.build_right_panel(right_frame)
        
        # 报告生成按钮
        report_btn = ttk.Button(left_frame, text="生成漏洞报告", command=self.generate_report)
        report_btn.pack(fill=tk.X, padx=5, pady=5)
        
        # 运行按钮
        run_btn = ttk.Button(left_frame, text="开始检测", command=self.run_scan, style='Accent.TButton')
        run_btn.pack(fill=tk.X, padx=5, pady=5)
    
    def build_left_panel(self, parent):
        """构建左侧选项面板"""
        # 基本设置
        basic_frame = ttk.LabelFrame(parent, text="基本设置")
        basic_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(basic_frame, text="测试级别 (1-5):").pack(anchor=tk.W, padx=5)
        ttk.Combobox(basic_frame, textvariable=self.level_var, values=["1", "2", "3", "4", "5"], width=5).pack(anchor=tk.W, padx=5, pady=2)
        
        ttk.Label(basic_frame, text="风险级别 (1-3):").pack(anchor=tk.W, padx=5)
        ttk.Combobox(basic_frame, textvariable=self.risk_var, values=["1", "2", "3"], width=5).pack(anchor=tk.W, padx=5, pady=2)
        
        ttk.Label(basic_frame, text="线程数:").pack(anchor=tk.W, padx=5)
        ttk.Entry(basic_frame, textvariable=self.threads_var, width=5).pack(anchor=tk.W, padx=5, pady=2)
        
        # 注入类型选择
        inj_frame = ttk.LabelFrame(parent, text="注入类型")
        inj_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(inj_frame, text="注入点类型:").pack(anchor=tk.W, padx=5)
        inj_types = ["GET", "POST", "Referer", "Cookie"]
        ttk.Combobox(inj_frame, textvariable=self.injection_type_var, values=inj_types, state="readonly").pack(anchor=tk.W, padx=5, pady=2)
        
        ttk.Label(inj_frame, text="Referer:").pack(anchor=tk.W, padx=5)
        ttk.Entry(inj_frame, textvariable=self.referer_var).pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(inj_frame, text="Cookie:").pack(anchor=tk.W, padx=5)
        ttk.Entry(inj_frame, textvariable=self.cookie_var).pack(fill=tk.X, padx=5, pady=2)
        
        # 检测选项
        detect_frame = ttk.LabelFrame(parent, text="检测选项")
        detect_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Checkbutton(detect_frame, text="获取当前数据库", variable=self.current_db_var).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(detect_frame, text="获取当前用户", variable=self.current_user_var).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(detect_frame, text="检测DBA权限", variable=self.is_dba_var).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(detect_frame, text="枚举数据库", variable=self.dbs_var).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(detect_frame, text="枚举表", variable=self.tables_var).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(detect_frame, text="枚举列", variable=self.columns_var).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(detect_frame, text="提取数据", variable=self.dump_var).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(detect_frame, text="全部提取", variable=self.dump_all_var).pack(anchor=tk.W, padx=5)
        
        # 数据库对象选择
        obj_frame = ttk.LabelFrame(parent, text="数据库对象选择")
        obj_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(obj_frame, text="数据库名:").pack(anchor=tk.W, padx=5)
        ttk.Entry(obj_frame, textvariable=self.db_var).pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(obj_frame, text="表名:").pack(anchor=tk.W, padx=5)
        ttk.Entry(obj_frame, textvariable=self.table_var).pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(obj_frame, text="列名 (逗号分隔):").pack(anchor=tk.W, padx=5)
        ttk.Entry(obj_frame, textvariable=self.column_var).pack(fill=tk.X, padx=5, pady=2)
        
        # WAF绕过选项
        waf_frame = ttk.LabelFrame(parent, text="WAF绕过选项")
        waf_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Checkbutton(waf_frame, text="随机User-Agent", variable=self.waf_bypass["random_agent"]).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(waf_frame, text="使用混淆脚本", variable=self.waf_bypass["tamper"]).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(waf_frame, text="分块传输", variable=self.waf_bypass["chunked"]).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(waf_frame, text="延迟请求", variable=self.waf_bypass["delay"]).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(waf_frame, text="伪造HTTP头", variable=self.waf_bypass["headers"]).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(waf_frame, text="跳过URL编码", variable=self.waf_bypass["skip_urlencode"]).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(waf_frame, text="Base64编码", variable=self.waf_bypass["base64"]).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(waf_frame, text="空格替换为注释", variable=self.waf_bypass["space2comment"]).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(waf_frame, text="字符编码", variable=self.waf_bypass["charencode"]).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(waf_frame, text="去除魔术引号", variable=self.waf_bypass["unmagicquotes"]).pack(anchor=tk.W, padx=5)
        
        # 其他选项
        other_frame = ttk.LabelFrame(parent, text="其他选项")
        other_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(other_frame, text="代理 (http://ip:port):").pack(anchor=tk.W, padx=5)
        ttk.Entry(other_frame, textvariable=self.proxy_var).pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Checkbutton(other_frame, text="默认应答", variable=self.batch_var).pack(anchor=tk.W, padx=5)
        
        ttk.Label(other_frame, text="注入技术:").pack(anchor=tk.W, padx=5)
        techniques = ["全选", "盲注", "报错注入", "堆叠注入", "联合查询", "时间注入", "内联查询"]
        ttk.Combobox(other_frame, textvariable=self.technique_var, values=techniques, state="readonly").pack(anchor=tk.W, padx=5, pady=2)
        
        ttk.Label(other_frame, text="数据库类型:").pack(anchor=tk.W, padx=5)
        dbms_types = ["", "MySQL", "Oracle", "PostgreSQL", "MSSQL", "SQLite", "Access"]
        ttk.Combobox(other_frame, textvariable=self.dbms_type_var, values=dbms_types).pack(anchor=tk.W, padx=5, pady=2)
    
    def build_middle_panel(self, parent):
        """构建中间面板"""
        # 目标URL输入
        ttk.Label(parent, text="目标URL:").pack(anchor=tk.W, padx=5)
        self.target_entry = ttk.Entry(parent, textvariable=self.target_url_var)
        self.target_entry.pack(fill=tk.X, padx=5, pady=2)
        
        # 数据包输入区域
        ttk.Label(parent, text="或输入HTTP请求包:").pack(anchor=tk.W, padx=5)
        self.request_text = Text(parent, height=10, wrap=tk.WORD)
        scroll = ttk.Scrollbar(self.request_text, command=self.request_text.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.request_text.config(yscrollcommand=scroll.set)
        self.request_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
        
        # 命令输出区域
        ttk.Label(parent, text="执行日志:").pack(anchor=tk.W, padx=5)
        self.output_text = Text(parent, height=15, wrap=tk.WORD, state=tk.DISABLED)
        scroll = ttk.Scrollbar(self.output_text, command=self.output_text.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_text.config(yscrollcommand=scroll.set)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
    
    def build_right_panel(self, parent):
        """构建右侧数据浏览面板"""
        # 创建数据浏览的PanedWindow
        data_paned = ttk.PanedWindow(parent, orient=tk.VERTICAL)
        data_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 数据库和表面板
        top_data_paned = ttk.PanedWindow(data_paned, orient=tk.HORIZONTAL)
        data_paned.add(top_data_paned, weight=1)
        
        # 列和数据面板
        bottom_data_paned = ttk.PanedWindow(data_paned, orient=tk.HORIZONTAL)
        data_paned.add(bottom_data_paned, weight=1)
        
        # 数据库列表
        db_frame = ttk.LabelFrame(top_data_paned, text="数据库")
        top_data_paned.add(db_frame, weight=1)
        
        self.db_listbox = tk.Listbox(db_frame)
        db_scroll = ttk.Scrollbar(self.db_listbox, command=self.db_listbox.yview)
        db_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.db_listbox.config(yscrollcommand=db_scroll.set)
        self.db_listbox.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # 表列表
        table_frame = ttk.LabelFrame(top_data_paned, text="表")
        top_data_paned.add(table_frame, weight=1)
        
        self.table_listbox = tk.Listbox(table_frame)
        table_scroll = ttk.Scrollbar(self.table_listbox, command=self.table_listbox.yview)
        table_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.table_listbox.config(yscrollcommand=table_scroll.set)
        self.table_listbox.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # 列列表
        column_frame = ttk.LabelFrame(bottom_data_paned, text="列")
        bottom_data_paned.add(column_frame, weight=1)
        
        self.column_listbox = tk.Listbox(column_frame, selectmode=tk.EXTENDED)
        column_scroll = ttk.Scrollbar(self.column_listbox, command=self.column_listbox.yview)
        column_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.column_listbox.config(yscrollcommand=column_scroll.set)
        self.column_listbox.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # 数据内容
        data_frame = ttk.LabelFrame(bottom_data_paned, text="数据")
        bottom_data_paned.add(data_frame, weight=1)
        
        self.data_text = Text(data_frame, wrap=tk.WORD)
        data_scroll = ttk.Scrollbar(self.data_text, command=self.data_text.yview)
        data_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.data_text.config(yscrollcommand=data_scroll.set)
        self.data_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
    
    def bind_events(self):
        """绑定事件处理"""
        # 列表选择事件
        self.db_listbox.bind('<<ListboxSelect>>', self.on_db_select)
        self.table_listbox.bind('<<ListboxSelect>>', self.on_table_select)
        self.column_listbox.bind('<<ListboxSelect>>', self.on_column_select)
        self.injection_type_var.trace_add('write', self.on_injection_type_change)
    
    def on_injection_type_change(self, *args):
        """注入类型改变时的处理"""
        inj_type = self.injection_type_var.get()
        # 根据注入类型显示/隐藏相关输入框
        if hasattr(self, 'inj_frame'):
            for child in self.inj_frame.winfo_children():
                if isinstance(child, ttk.Label) and child['text'] in ["Referer:", "Cookie:"]:
                    label_text = child['text']
                    entry_widget = child.next
                    if (label_text == "Referer:" and inj_type == "Referer") or \
                       (label_text == "Cookie:" and inj_type == "Cookie"):
                        child.pack(anchor=tk.W, padx=5)
                        entry_widget.pack(fill=tk.X, padx=5, pady=2)
                    else:
                        child.pack_forget()
                        entry_widget.pack_forget()
    
    def on_db_select(self, event):
        """选择数据库时的处理"""
        selection = self.db_listbox.curselection()
        if selection:
            db_name = self.db_listbox.get(selection[0])
            self.db_var.set(db_name)
            # 自动加载表列表
            url = self.target_url_var.get() or "http://example.com"
            options = self.get_options()
            tables = self.sqlmap_core.detect_tables(db_name, url, options)
            self.update_table_list(tables)
    
    def on_table_select(self, event):
        """选择表时的处理"""
        selection = self.table_listbox.curselection()
        if selection:
            table_name = self.table_listbox.get(selection[0])
            self.table_var.set(table_name)
            # 自动加载列列表
            db_name = self.db_var.get()
            if db_name:
                url = self.target_url_var.get() or "http://example.com"
                options = self.get_options()
                columns = self.sqlmap_core.detect_columns(db_name, table_name, url, options)
                self.update_column_list(columns)
    
    def on_column_select(self, event):
        """选择列时的处理"""
        selections = self.column_listbox.curselection()
        if selections:
            columns = [self.column_listbox.get(i) for i in selections]
            self.column_var.set(",".join(columns))
    
    def update_db_list(self, databases):
        """更新数据库列表"""
        self.db_listbox.delete(0, tk.END)
        for db in databases:
            self.db_listbox.insert(tk.END, db)
    
    def update_table_list(self, tables):
        """更新表列表"""
        self.table_listbox.delete(0, tk.END)
        for table in tables:
            self.table_listbox.insert(tk.END, table)
    
    def update_column_list(self, columns):
        """更新列列表"""
        self.column_listbox.delete(0, tk.END)
        for column in columns:
            self.column_listbox.insert(tk.END, column)
    
    def update_data_display(self, data):
        """更新数据显示"""
        self.data_text.delete(1.0, tk.END)
        if data and isinstance(data[0], tuple):
            # 如果是元组列表，说明有多列数据
            for row in data:
                self.data_text.insert(tk.END, "\t".join(map(str, row)) + "\n")
        elif data:
            # 单列数据
            for item in data:
                self.data_text.insert(tk.END, str(item) + "\n")
    
    def log(self, message):
        """在日志区域显示消息"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.root.update_idletasks()
    
    def get_options(self):
        """获取当前选项设置"""
        options = {
            'url': self.target_url_var.get(),
            'level': self.level_var.get(),
            'risk': self.risk_var.get(),
            'threads': self.threads_var.get(),
            'current-db': self.current_db_var.get(),
            'current-user': self.current_user_var.get(),
            'is-dba': self.is_dba_var.get(),
            'dbs': self.dbs_var.get(),
            'tables': self.tables_var.get(),
            'columns': self.columns_var.get(),
            'dump': self.dump_var.get(),
            'dump-all': self.dump_all_var.get(),
            'proxy': self.proxy_var.get(),
            'batch': self.batch_var.get(),
            'technique': self.technique_var.get(),
            'dbms': self.dbms_type_var.get(),
            'injection-type': self.injection_type_var.get(),
            'referer': self.referer_var.get(),
            'cookie': self.cookie_var.get(),
            'D': self.db_var.get(),
            'T': self.table_var.get(),
            'C': self.column_var.get(),
            'waf-bypass': {k: v.get() for k, v in self.waf_bypass.items()}
        }
        
        return options
    
    def run_scan(self):
        """执行扫描"""
        # 清空之前的日志
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        
        # 获取选项
        options = self.get_options()
        
        # 验证目标
        if not options['url'] and not self.request_text.get(1.0, tk.END).strip():
            msgbox.showerror("错误", "请输入目标URL或HTTP请求包")
            return
        
        self.log("开始SQL注入检测...")
        self.log(f"目标: {options['url'] or '从请求包获取'}")
        self.log(f"注入类型: {options['injection-type']}")
        
        # 执行SQLmap核心功能
        result = self.sqlmap_core.run(options)
        
        # 处理结果
        for msg in result['message']:
            self.log(msg)
        
        # 更新界面数据
        if 'databases' in result['data']:
            self.update_db_list(result['data']['databases'])
        
        if 'tables' in result['data']:
            self.update_table_list(result['data']['tables'])
        
        if 'columns' in result['data']:
            self.update_column_list(result['data']['columns'])
        
        if 'data' in result['data']:
            self.update_data_display(result['data']['data'])
        
        self.log("检测完成")
    
    def generate_report(self):
        """生成漏洞利用报告"""
        # 创建报告窗口
        report_window = tk.Toplevel(self.root)
        report_window.title("生成漏洞利用报告")
        report_window.geometry("600x400")
        report_window.transient(self.root)
        report_window.grab_set()
        
        # 报告内容设置
        frame = ttk.Frame(report_window, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="漏洞利用报告设置", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=10)
        
        # 报告格式选择
        format_frame = ttk.Frame(frame)
        format_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(format_frame, text="报告格式:").pack(side=tk.LEFT, padx=5)
        report_format = tk.StringVar(value="txt")
        ttk.Radiobutton(format_frame, text="文本文件 (.txt)", variable=report_format, value="txt").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="HTML文件 (.html)", variable=report_format, value="html").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="JSON文件 (.json)", variable=report_format, value="json").pack(side=tk.LEFT, padx=5)
        
        # 报告内容选项
        ttk.Label(frame, text="报告包含内容:").pack(anchor=tk.W, pady=5)
        
        include_dbs = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="数据库信息", variable=include_dbs).pack(anchor=tk.W, padx=20)
        
        include_tables = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="表信息", variable=include_tables).pack(anchor=tk.W, padx=20)
        
        include_columns = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="列信息", variable=include_columns).pack(anchor=tk.W, padx=20)
        
        include_data = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="提取的数据", variable=include_data).pack(anchor=tk.W, padx=20)
        
        include_tech = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="使用的技术和选项", variable=include_tech).pack(anchor=tk.W, padx=20)
        
        # 按钮区域
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=20)
        
        def save_report():
            """保存报告"""
            # 获取保存路径
            ext = report_format.get()
            filename = filedialog.asksaveasfilename(
                defaultextension=f".{ext}",
                filetypes=[
                    (f"{ext.upper()}文件", f"*.{ext}"),
                    ("所有文件", "*.*")
                ],
                initialfile=f"sql_injection_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            
            if not filename:
                return
            
            # 收集报告数据
            options = self.get_options()
            results = self.sqlmap_core.current_results
            
            report_data = {
                "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target": options['url'] or "从请求包获取",
                "injection_type": options['injection-type'],
                "technique": options['technique'],
                "waf_bypass_used": [k for k, v in self.waf_bypass.items() if v.get()],
                "databases": results.get('databases', []),
                "tables": results.get('tables', []),
                "columns": results.get('columns', []),
                "data": results.get('data', [])
            }
            
            # 生成报告内容
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    if ext == 'txt':
                        f.write("SQL注入漏洞利用报告\n")
                        f.write("="*50 + "\n\n")
                        f.write(f"生成时间: {report_data['generated']}\n")
                        f.write(f"目标: {report_data['target']}\n")
                        f.write(f"注入类型: {report_data['injection_type']}\n")
                        f.write(f"使用技术: {report_data['technique']}\n")
                        if report_data['waf_bypass_used']:
                            f.write(f"WAF绕过方法: {', '.join(report_data['waf_bypass_used'])}\n\n")
                        
                        if include_dbs.get() and report_data['databases']:
                            f.write("发现的数据库:\n")
                            f.write("-"*30 + "\n")
                            for db in report_data['databases']:
                                f.write(f"- {db}\n")
                            f.write("\n")
                        
                        if include_tables.get() and report_data['tables']:
                            f.write("发现的表:\n")
                            f.write("-"*30 + "\n")
                            for table in report_data['tables']:
                                f.write(f"- {table}\n")
                            f.write("\n")
                        
                        if include_columns.get() and report_data['columns']:
                            f.write("发现的列:\n")
                            f.write("-"*30 + "\n")
                            for column in report_data['columns']:
                                f.write(f"- {column}\n")
                            f.write("\n")
                        
                        if include_data.get() and report_data['data']:
                            f.write("提取的数据:\n")
                            f.write("-"*30 + "\n")
                            for row in report_data['data']:
                                if isinstance(row, tuple):
                                    f.write("\t".join(map(str, row)) + "\n")
                                else:
                                    f.write(f"- {row}\n")
                
                    elif ext == 'html':
                        f.write("<!DOCTYPE html>\n<html>\n<head>\n")
                        f.write("<title>SQL注入漏洞利用报告</title>\n")
                        f.write("<style>\n")
                        f.write("body { font-family: Arial, sans-serif; margin: 20px; }\n")
                        f.write("h1 { color: #2c3e50; }\n")
                        f.write(".section { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }\n")
                        f.write("table { border-collapse: collapse; width: 100%; margin: 10px 0; }\n")
                        f.write("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n")
                        f.write("th { background-color: #f2f2f2; }\n")
                        f.write("</style>\n</head>\n<body>\n")
                        
                        f.write(f"<h1>SQL注入漏洞利用报告</h1>\n")
                        f.write(f"<p>生成时间: {report_data['generated']}</p>\n")
                        f.write(f"<p>目标: {report_data['target']}</p>\n")
                        f.write(f"<p>注入类型: {report_data['injection_type']}</p>\n")
                        f.write(f"<p>使用技术: {report_data['technique']}</p>\n")
                        
                        if report_data['waf_bypass_used']:
                            f.write(f"<p>WAF绕过方法: {', '.join(report_data['waf_bypass_used'])}</p>\n")
                        
                        if include_dbs.get() and report_data['databases']:
                            f.write("<div class='section'>\n")
                            f.write("<h2>发现的数据库</h2>\n")
                            f.write("<ul>\n")
                            for db in report_data['databases']:
                                f.write(f"<li>{db}</li>\n")
                            f.write("</ul>\n</div>\n")
                        
                        if include_tables.get() and report_data['tables']:
                            f.write("<div class='section'>\n")
                            f.write("<h2>发现的表</h2>\n")
                            f.write("<ul>\n")
                            for table in report_data['tables']:
                                f.write(f"<li>{table}</li>\n")
                            f.write("</ul>\n</div>\n")
                        
                        if include_columns.get() and report_data['columns']:
                            f.write("<div class='section'>\n")
                            f.write("<h2>发现的列</h2>\n")
                            f.write("<ul>\n")
                            for column in report_data['columns']:
                                f.write(f"<li>{column}</li>\n")
                            f.write("</ul>\n</div>\n")
                        
                        if include_data.get() and report_data['data']:
                            f.write("<div class='section'>\n")
                            f.write("<h2>提取的数据</h2>\n")
                            f.write("<table>\n")
                            
                            # 如果是元组列表，创建表头
                            if report_data['data'] and isinstance(report_data['data'][0], tuple):
                                f.write("<tr>\n")
                                for i in range(len(report_data['data'][0])):
                                    f.write(f"<th>列 {i+1}</th>\n")
                                f.write("</tr>\n")
                            
                            for row in report_data['data']:
                                f.write("<tr>\n")
                                if isinstance(row, tuple):
                                    for item in row:
                                        f.write(f"<td>{item}</td>\n")
                                else:
                                    f.write(f"<td>{row}</td>\n")
                                f.write("</tr>\n")
                            f.write("</table>\n</div>\n")
                        
                        f.write("</body>\n</html>")
                    
                    elif ext == 'json':
                        json.dump(report_data, f, ensure_ascii=False, indent=2)
                
                msgbox.showinfo("成功", f"报告已保存至:\n{filename}")
                report_window.destroy()
                
            except Exception as e:
                msgbox.showerror("错误", f"保存报告失败:\n{str(e)}")
        
        ttk.Button(btn_frame, text="选择保存位置", command=save_report).pack(fill=tk.X)
        
        # 显示报告窗口
        report_window.geometry(f"+{self.root.winfo_x() + 50}+{self.root.winfo_y() + 50}")


if __name__ == "__main__":
    root = tk.Tk()
    # 设置ttk样式
    style = ttk.Style()
    style.configure('Accent.TButton', font=('Arial', 10, 'bold'))
    app = SQLmapGUI(root)
    root.mainloop()
