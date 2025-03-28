# -*- coding: utf-8 -*-
from burp import IBurpExtender
import threading
import json
import BaseHTTPServer
import urlparse

burp_callbacks = None

class ScanRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_POST(self):
        global burp_callbacks

        if self.path != "/scan":
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Not found"}))
            return

        content_length = int(self.headers.getheader('Content-Length') or 0)
        post_data = self.rfile.read(content_length)

        try:
            data = json.loads(post_data)
            url = data.get("url")

            if not url:
                raise ValueError("Missing 'url' in request")

            # Trigger Burp active scan
            from java.net import URL
            import java.lang.String as JString

            helpers = burp_callbacks.getHelpers()
            parsed_url = URL(url)

            host = parsed_url.getHost()
            protocol = parsed_url.getProtocol()
            port = parsed_url.getPort()
            if port == -1:
                port = 443 if protocol == "https" else 80

            print("[DEBUG] Parsed URL - Host: {}, Port: {}, Protocol: {}".format(host, port, protocol))

            if not host or not protocol:
                raise Exception("Invalid URL. Missing host or protocol.")

            # Force cast to Java Strings
            service = helpers.buildHttpService(JString(host), port, JString(protocol))
            request_bytes = helpers.buildHttpRequest(parsed_url)

            start = 0
            end = len(request_bytes)
            burp_callbacks.doActiveScan(service, request_bytes, start, end)
            print("[DEBUG] Active scan triggered for {}".format(url))




            response_body = json.dumps({"message": "Scan triggered for {}".format(url)})
            self.send_response(200)

        except Exception as e:
            response_body = json.dumps({"error": str(e)})
            self.send_response(500)

        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        try:
            self.wfile.write(response_body)
            self.wfile.flush()
        except Exception as e:
            print("[ERROR] Failed to flush response:", str(e))
    


    def log_message(self, format, *args):
        return

def start_http_server():
    server = BaseHTTPServer.HTTPServer(('localhost', 5001), ScanRequestHandler)
    print("[INFO] Starting HTTP server on http://localhost:5001/scan ...")
    server.serve_forever()

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        global burp_callbacks
        burp_callbacks = callbacks
        burp_callbacks.setExtensionName("Burp Scan HTTP Server")

        print("[INFO] Extension loaded. Launching HTTP server...")
        thread = threading.Thread(target=start_http_server)
        thread.setDaemon(True)
        thread.start()
