from burp import IBurpExtender, ITab
from burp import IContextMenuFactory
from burp import IHttpService, IHttpRequestResponse
from javax.swing import JPanel, JTextArea, JButton, JScrollPane, JLabel
from java.awt import BorderLayout, Font, Dimension, FlowLayout  # Import FlowLayout from java.awt
import re

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("cURL to Repeater")
        
        self._panel = JPanel()
        self._panel.setLayout(BorderLayout())
        
        # Add label with bold text and centered
        label = JLabel("Paste the cURL request in bash format ")
        label.setFont(label.getFont().deriveFont(Font.BOLD))
        label.setHorizontalAlignment(JLabel.CENTER)
        
        # Add some space below the label
        label.setPreferredSize(Dimension(400, 50))
        
        self._textArea = JTextArea(15, 40)  # Adjusted the size to be medium
        scrollPane = JScrollPane(self._textArea)
        
        # Add buttons
        button_panel = JPanel()
        button_panel.setLayout(FlowLayout(FlowLayout.CENTER))  # Centering buttons
        
        self._send_button = JButton("Send request to Repeater", actionPerformed=self.sendToRepeater)
        self._clear_button = JButton("Clear", actionPerformed=self.clearTextArea)
        
        button_panel.add(self._send_button)
        button_panel.add(self._clear_button)
        
        self._panel.add(label, BorderLayout.NORTH)  # Add label at the top
        self._panel.add(scrollPane, BorderLayout.CENTER)
        self._panel.add(button_panel, BorderLayout.SOUTH)
        
        callbacks.addSuiteTab(self)
        
        return
    
    def getTabCaption(self):
        return "cURL to Repeater"
    
    def getUiComponent(self):
        return self._panel
    
    def sendToRepeater(self, event):
        curl_command = self._textArea.getText()
        http_service, request = self.parse_curl_command(curl_command)
        if http_service and request:
            self._callbacks.sendToRepeater(http_service.getHost(), http_service.getPort(), http_service.getProtocol() == "https", request, None)
    
    def clearTextArea(self, event):
        self._textArea.setText("")
    
    def parse_curl_command(self, curl_command):
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
