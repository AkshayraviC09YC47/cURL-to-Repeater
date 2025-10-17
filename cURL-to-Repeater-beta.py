from burp import IBurpExtender, ITab
from burp import IContextMenuFactory
from burp import IHttpService, IHttpRequestResponse
from javax.swing import JPanel, JTextArea, JButton, JScrollPane, JLabel
from java.awt import BorderLayout, Font, Dimension, GridLayout, FlowLayout
import re
import base64
import json

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("cURL to Repeater")
        
        self._panel = JPanel()
        self._panel.setLayout(GridLayout(1, 2))
        
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
            self._callbacks.sendToRepeater(http_service.getHost(), http_service.getPort(), 
                                          http_service.getProtocol() == "https", request, None)
    
    def sendCmdToRepeater(self, event):
        curl_command = self._cmd_text_area.getText()
        http_service, request = self.parse_curl_command(curl_command, format="cmd")
        if http_service and request:
            self._callbacks.sendToRepeater(http_service.getHost(), http_service.getPort(), 
                                          http_service.getProtocol() == "https", request, None)
    
    def clearBashTextArea(self, event):
        self._bash_text_area.setText("")
    
    def clearCmdTextArea(self, event):
        self._cmd_text_area.setText("")
    
    def detect_content_type(self, headers):
        """Extract Content-Type from headers"""
        for header in headers:
            if header.lower().startswith('content-type:'):
                return header.split(':', 1)[1].strip()
        return None
    
    def parse_data_based_on_content_type(self, data, content_type):
        """Handle different content types appropriately"""
        if not data or not content_type:
            return data
        
        content_type_lower = content_type.lower()
        
        # Handle URL-encoded data
        if 'application/x-www-form-urlencoded' in content_type_lower:
            # Data is already in the correct format from curl
            return data
        
        # Handle JSON
        elif 'application/json' in content_type_lower:
            # Validate and pretty-print if needed
            try:
                json_obj = json.loads(data)
                return data  # Return as-is if valid
            except:
                return data
        
        # Handle XML (both application/xml and text/xml)
        elif 'xml' in content_type_lower:
            return data
        
        # Handle plain text formats
        elif any(t in content_type_lower for t in ['text/plain', 'text/html', 'text/css', 
                                                     'text/csv', 'application/javascript']):
            return data
        
        # Handle multipart form data
        elif 'multipart/' in content_type_lower:
            # Multipart data should already be properly formatted in curl
            return data
        
        # Handle binary data (PDF, ZIP, images, audio, video, octet-stream)
        elif any(t in content_type_lower for t in ['application/pdf', 'application/zip', 
                                                     'application/octet-stream',
                                                     'image/', 'audio/', 'video/']):
            # Check if data is base64 encoded
            try:
                # Try to decode if it looks like base64
                if re.match(r'^[A-Za-z0-9+/]*={0,2}$', data.replace('\n', '').replace('\r', '')):
                    decoded = base64.b64decode(data)
                    return decoded
            except:
                pass
            return data
        
        return data
    
    def parse_curl_command(self, curl_command, format):
        """Enhanced parser supporting all content types"""
        
        # Parse based on format (bash or cmd)
        if format == "bash":
            url_match = re.search(r'curl\s+[\'"]?(https?://[^\s\'"]+)[\'"]?', curl_command)
            if not url_match:
                return None, None
            
            url = url_match.group(1)
            method = "GET"
            headers = []
            data = None
            binary_data = None
            
            # Extract method
            method_match = re.search(r'-X\s+[\'"]?(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)[\'"]?', curl_command, re.IGNORECASE)
            if method_match:
                method = method_match.group(1).upper()
            elif '--data' in curl_command or '--form' in curl_command:
                method = "POST"
            
            # Extract headers
            headers = re.findall(r'-H\s+[\'"]([^\'"]+)[\'"]', curl_command)
            
            # Extract data (multiple formats)
            # --data-raw, --data, --data-binary, -d
            data_match = re.search(r'--data-raw\s+[\'"](.+?)[\'"]', curl_command, re.DOTALL)
            if not data_match:
                data_match = re.search(r'--data-binary\s+[\'"](.+?)[\'"]', curl_command, re.DOTALL)
            if not data_match:
                data_match = re.search(r'--data\s+[\'"](.+?)[\'"]', curl_command, re.DOTALL)
            if not data_match:
                data_match = re.search(r'-d\s+[\'"](.+?)[\'"]', curl_command, re.DOTALL)
            
            if data_match:
                data = data_match.group(1)
            
            # Extract form data (multipart)
            form_matches = re.findall(r'--form\s+[\'"]([^\'"]+)[\'"]', curl_command)
            if form_matches:
                # Build multipart form data
                boundary = "----WebKitFormBoundary" + "".join([str(ord(c)) for c in url[:16]])
                multipart_data = ""
                for form_field in form_matches:
                    multipart_data += "--%s\r\n" % boundary
                    if '=@' in form_field:
                        # File upload
                        field_name, file_path = form_field.split('=@', 1)
                        multipart_data += 'Content-Disposition: form-data; name="%s"; filename="%s"\r\n' % (field_name, file_path.split('/')[-1])
                        multipart_data += 'Content-Type: application/octet-stream\r\n\r\n'
                        multipart_data += '[FILE_CONTENT_HERE]\r\n'
                    else:
                        # Regular field
                        field_name, field_value = form_field.split('=', 1)
                        multipart_data += 'Content-Disposition: form-data; name="%s"\r\n\r\n' % field_name
                        multipart_data += '%s\r\n' % field_value
                multipart_data += "--%s--\r\n" % boundary
                data = multipart_data
                # Add multipart content-type header if not present
                has_content_type = any('content-type' in h.lower() for h in headers)
                if not has_content_type:
                    headers.append('Content-Type: multipart/form-data; boundary=%s' % boundary)
        
        elif format == "cmd":
            url_match = re.search(r'curl\s+"(https?://[^"]+)"', curl_command)
            if not url_match:
                url_match = re.search(r'curl\s+(https?://[^\s]+)', curl_command)
            if not url_match:
                return None, None
            
            url = url_match.group(1)
            method = "GET"
            headers = []
            data = None
            
            # Extract method
            method_match = re.search(r'-X\s+"?(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)"?', curl_command, re.IGNORECASE)
            if method_match:
                method = method_match.group(1).upper()
            elif '--data' in curl_command or '--form' in curl_command:
                method = "POST"
            
            # Extract headers
            headers = re.findall(r'-H\s+"([^"]+)"', curl_command)
            
            # Extract data
            data_match = re.search(r'--data(?:-raw|-binary)?\s+"(.+?)"', curl_command, re.DOTALL)
            if not data_match:
                data_match = re.search(r'-d\s+"(.+?)"', curl_command, re.DOTALL)
            
            if data_match:
                data = data_match.group(1)
            
            # Extract form data
            form_matches = re.findall(r'--form\s+"([^"]+)"', curl_command)
            if form_matches:
                boundary = "----WebKitFormBoundary" + "".join([str(ord(c)) for c in url[:16]])
                multipart_data = ""
                for form_field in form_matches:
                    multipart_data += "--%s\r\n" % boundary
                    if '=@' in form_field:
                        field_name, file_path = form_field.split('=@', 1)
                        multipart_data += 'Content-Disposition: form-data; name="%s"; filename="%s"\r\n' % (field_name, file_path.split('\\')[-1])
                        multipart_data += 'Content-Type: application/octet-stream\r\n\r\n'
                        multipart_data += '[FILE_CONTENT_HERE]\r\n'
                    else:
                        field_name, field_value = form_field.split('=', 1)
                        multipart_data += 'Content-Disposition: form-data; name="%s"\r\n\r\n' % field_name
                        multipart_data += '%s\r\n' % field_value
                multipart_data += "--%s--\r\n" % boundary
                data = multipart_data
                has_content_type = any('content-type' in h.lower() for h in headers)
                if not has_content_type:
                    headers.append('Content-Type: multipart/form-data; boundary=%s' % boundary)
        
        # Parse URL
        parsed_url = re.search(r'(https?)://([^/:]+)(?::(\d+))?(/.*)?', url)
        if not parsed_url:
            return None, None
        
        protocol = parsed_url.group(1)
        host = parsed_url.group(2)
        port = parsed_url.group(3)
        path = parsed_url.group(4) if parsed_url.group(4) else '/'
        
        # Determine port
        if port:
            port = int(port)
        else:
            port = 443 if protocol == "https" else 80
        
        # Build HTTP request
        request = "%s %s HTTP/1.1\r\n" % (method, path)
        request += "Host: %s\r\n" % host
        
        # Add headers
        content_type = None
        has_content_length = False
        
        for header in headers:
            if header.lower().startswith('content-type:'):
                content_type = header.split(':', 1)[1].strip()
            if header.lower().startswith('content-length:'):
                has_content_length = True
            request += "%s\r\n" % header
        
        # Process data based on content type
        if data:
            processed_data = self.parse_data_based_on_content_type(data, content_type)
            
            # Add Content-Length if not present and we have data
            if not has_content_length:
                if isinstance(processed_data, str):
                    content_length = len(processed_data)
                else:
                    content_length = len(str(processed_data))
                request += "Content-Length: %d\r\n" % content_length
        
        request += "\r\n"
        
        # Add body data
        if data:
            processed_data = self.parse_data_based_on_content_type(data, content_type)
            if isinstance(processed_data, str):
                request += processed_data
            else:
                # Handle binary data
                request_bytes = self._helpers.stringToBytes(request)
                if isinstance(processed_data, (bytes, bytearray)):
                    # Combine request and binary data
                    combined = bytearray(request_bytes)
                    combined.extend(processed_data)
                    http_service = self._helpers.buildHttpService(host, port, protocol == "https")
                    return http_service, bytes(combined)
                else:
                    request += str(processed_data)
        
        http_service = self._helpers.buildHttpService(host, port, protocol == "https")
        
        return http_service, self._helpers.stringToBytes(request)
