from burp import IBurpExtender, ITab
from burp import IContextMenuFactory
from burp import IHttpService, IHttpRequestResponse
from javax.swing import JPanel, JTextArea, JButton, JScrollPane, JLabel
from java.awt import BorderLayout, Font, Dimension, GridLayout, FlowLayout
import re

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("cURL to Repeater")
        
        self._panel = JPanel()
        self._panel.setLayout(GridLayout(1, 2))  # Two panels side by side
        
        # Panel for bash format
        bash_panel = JPanel()
        bash_panel.setLayout(BorderLayout())
        
        bash_label = JLabel("Paste the cURL request in bash format (Linux)")
        bash_label.setFont(bash_label.getFont().deriveFont(Font.BOLD))
        bash_label.setHorizontalAlignment(JLabel.CENTER)
        bash_label.setPreferredSize(Dimension(400, 50))
        
        self._bash_text_area = JTextArea(15, 40)
        bash_scroll_pane = JScrollPane(self._bash_text_area)
        
        bash_button_panel = JPanel()
        bash_button_panel.setLayout(FlowLayout(FlowLayout.CENTER))
        
        self._bash_send_button = JButton("Send cURL bash request to Repeater", actionPerformed=self.sendBashToRepeater)
        self._bash_clear_button = JButton("Clear bash", actionPerformed=self.clearBashTextArea)
        
        bash_button_panel.add(self._bash_send_button)
        bash_button_panel.add(self._bash_clear_button)
        
        bash_panel.add(bash_label, BorderLayout.NORTH)
        bash_panel.add(bash_scroll_pane, BorderLayout.CENTER)
        bash_panel.add(bash_button_panel, BorderLayout.SOUTH)
        
        # Panel for cmd format
        cmd_panel = JPanel()
        cmd_panel.setLayout(BorderLayout())
        
        cmd_label = JLabel("Paste the cURL request in cmd format (Windows)")
        cmd_label.setFont(cmd_label.getFont().deriveFont(Font.BOLD))
        cmd_label.setHorizontalAlignment(JLabel.CENTER)
        cmd_label.setPreferredSize(Dimension(400, 50))
        
        self._cmd_text_area = JTextArea(15, 40)
        cmd_scroll_pane = JScrollPane(self._cmd_text_area)
        
        cmd_button_panel = JPanel()
        cmd_button_panel.setLayout(FlowLayout(FlowLayout.CENTER))
        
        self._cmd_send_button = JButton("Send cURL cmd request to Repeater", actionPerformed=self.sendCmdToRepeater)
        self._cmd_clear_button = JButton("Clear cmd", actionPerformed=self.clearCmdTextArea)
        
        cmd_button_panel.add(self._cmd_send_button)
        cmd_button_panel.add(self._cmd_clear_button)
        
        cmd_panel.add(cmd_label, BorderLayout.NORTH)
        cmd_panel.add(cmd_scroll_pane, BorderLayout.CENTER)
        cmd_panel.add(cmd_button_panel, BorderLayout.SOUTH)
        
        # Add sub-panels to main panel
        self._panel.add(bash_panel)
        self._panel.add(cmd_panel)
        
        callbacks.addSuiteTab(self)
        
        return
    
    def getTabCaption(self):
        return "cURL to Repeater"
    
    def getUiComponent(self):
        return self._panel
    
    def sendBashToRepeater(self, event):
        curl_command = self._bash_text_area.getText()
        http_service, request = self.parse_curl_command(curl_command, format="bash")
        if http_service and request:
            self._callbacks.sendToRepeater(http_service.getHost(), http_service.getPort(), http_service.getProtocol() == "https", request, None)
    
    def sendCmdToRepeater(self, event):
        curl_command = self._cmd_text_area.getText()
        http_service, request = self.parse_curl_command(curl_command, format="cmd")
        if http_service and request:
            self._callbacks.sendToRepeater(http_service.getHost(), http_service.getPort(), http_service.getProtocol() == "https", request, None)
    
    def clearBashTextArea(self, event):
        self._bash_text_area.setText("")
    
    def clearCmdTextArea(self, event):
        self._cmd_text_area.setText("")
    
    def parse_curl_command(self, curl_command, format):
        if format == "bash":
            url_match = re.search(r'curl \'(.*?)\'', curl_command)
            if not url_match:
                return None, None
            
            url = url_match.group(1)
            method = "GET"
            headers = []
            data = None
            
            if re.search(r'-X (POST|PUT|DELETE|OPTIONS|HEAD)', curl_command):
                method = re.search(r'-X (POST|PUT|DELETE|OPTIONS|HEAD)', curl_command).group(1)
            
            headers = re.findall(r'-H \'(.*?)\'', curl_command)
            data_match = re.search(r'--data-raw \'(.*?)\'', curl_command)
            if data_match:
                data = data_match.group(1)
        
        elif format == "cmd":
            url_match = re.search(r'curl\s+"(.*?)"', curl_command)
            if not url_match:
                return None, None
            
            url = url_match.group(1)
            method = "GET"
            headers = []
            data = None
            
            if re.search(r'-X (POST|PUT|DELETE|OPTIONS|HEAD)', curl_command):
                method = re.search(r'-X (POST|PUT|DELETE|OPTIONS|HEAD)', curl_command).group(1)
            
            headers = re.findall(r'-H "(.*?)"', curl_command)
            data_match = re.search(r'--data(?:-raw)? "(.*?)"', curl_command)
            if data_match:
                data = data_match.group(1)
        
        parsed_url = re.search(r'https?://([^/]+)(/.*)?', url)
        host = parsed_url.group(1)
        path = parsed_url.group(2) if parsed_url.group(2) else '/'
        
        request = "%s %s HTTP/1.1\r\n" % (method, path)
        request += "Host: %s\r\n" % host
        
        for header in headers:
            request += "%s\r\n" % header
        
        request += "\r\n"
        
        if data:
            request += data
        
        http_service = self._helpers.buildHttpService(host, 443 if url.startswith("https") else 80, url.startswith("https"))
        
        return http_service, self._helpers.stringToBytes(request)
