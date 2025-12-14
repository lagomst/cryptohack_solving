# burp_server_material_extractor.py

import time
from burp import IBurpExtender, IHttpListener
import json
import os
import socket
import sys

OUTPUT_FILE = "server.txt"
INPUT_FILE = "fake.txt"

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65431     # The port used by the server

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SMC Server Material Extractor")
        callbacks.registerHttpListener(self)
        print("[+] SMC Server Material Extractor loaded")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            requestInfo = self.helpers.analyzeRequest(messageInfo)
            headers = list(requestInfo.getHeaders() or '') 
            url = requestInfo.getUrl().toString()         
            new_data = None
            if "/session/exchange" in url:
                print("Exchange client spotted! Intercepting...")
                data = self.extract_client_request(messageInfo.getRequest(), url)
                # print("Data to be sent: ", data)
                new_data = send_to_python3("Exchange client:" + json.dumps(data))

            if "/message/send" in url:
                print("Client sending a message! Intercepting...")
                data = self.extract_client_request(messageInfo.getRequest(), url)
                new_data = send_to_python3("Msg client:" + json.dumps(data))
                
            if new_data:
                # print("Server response: ", new_data)
                status, _, new_body = new_data.partition(':')
                if status == "success":
                    print("Replacing request")
                    new_message_bytes = self.helpers.buildHttpMessage(headers, new_body)
                    messageInfo.setRequest(new_message_bytes)
                    print("Request successfully replaced")
            return

        response = messageInfo.getResponse()
        if response is None:
            return

        request_info = self.helpers.analyzeRequest(messageInfo)
        headers = list(request_info.getHeaders() or '')
        url = request_info.getUrl().toString()
        new_data = None
        if "/session/create" in url:
            print("Login response found! Intercepting...")
            
            # 1. Analyze the original response to get the headers
            response_info = self.helpers.analyzeResponse(messageInfo.getResponse())
            original_headers = response_info.getHeaders()
            
            # 2. Extract and process the original message data
            # Assuming this function gets the original data structure
            data = self.extract_server_response(messageInfo.getResponse(), url) 
            
            # 3. Send to Python 3 and get the new body content back
            # NOTE: new_data must be the raw *body* string/bytes
            new_data = send_to_python3("Login server:" + json.dumps(data)) 
        
        if "/message/send" in url:
            print("Server sending a response! Intercepting...")
            response_info = self.helpers.analyzeResponse(messageInfo.getResponse())
            original_headers = response_info.getHeaders()

            data = self.extract_server_response(messageInfo.getResponse(), url) 
            new_data = send_to_python3("Msg server:" + json.dumps(data)) 
            
        if new_data:
            status, _, new_body = new_data.partition(':')
            if status == "success":    
                new_message_bytes = self.helpers.buildHttpMessage(original_headers, new_body)

                messageInfo.setResponse(new_message_bytes)
                print("Response successfully replaced.")
        
        # if "/session/exchange" in url:
        #     print("Exchange found")
        #     data = self.extract_server_response(response, url)
        #     new_data = send_to_python3("Exchange server:" + json.dumps(data))
        #     new_message = self.helpers.buildHttpMessage(headers, new_data)
        #     messageInfo.setResponse(new_message)
        

        return
    
    def extract_client_request(self, request, url):
        print("Extracting client request")
        request_info = self.helpers.analyzeRequest(request)
        body_offset = request_info.getBodyOffset()
        
        # Use the robust Burp helper function to get the body as a string
        body_bytes = request[body_offset:]
        body = self.helpers.bytesToString(body_bytes)

        try:
            data = json.loads(body)
        except:
            print("Exception occur")
            return {}

        # self.save_server_material(data, url)
        return data
    
    def extract_server_response(self, response, url):
        response_info = self.helpers.analyzeResponse(response)
        body_offset = response_info.getBodyOffset()
        body_bytes = response[body_offset:]
        body = self.helpers.bytesToString(body_bytes)

        try:
            data = json.loads(body)
        except:
            return

        if not data.get("success"):
            return

        # self.save_server_material(data, url)
        return data


    def save_server_material(self, data, url):
        server_data = {
            "url": url,
            "sessionToken": data.get("sessionToken"),
            "kexAlgorithm": data.get("algorithm"),
            "serverPublicKey": data.get("serverPublicKey"),
            "serverSignaturePublicKey": data.get("serverSignaturePublicKey"),
            "sessionSignature": data.get("sessionSignature"),
            "signatureAlgorithm": data.get("signatureAlgorithm")
        }

        try:
            with open(OUTPUT_FILE, "w") as f:
                json.dump(server_data, f, indent=2)
            print("[+] Server material saved to %s" % OUTPUT_FILE)
        except Exception as e:
            print("[-] Failed to write server.txt:", e)

# This class/function manages the socket connection and buffers data
class SocketReader:
    def __init__(self, sock):
        self.sock = sock
        # Initialize a buffer for incoming bytes
        self.buffer = b'' 
        
    def read_until(self, delimiter=b'\n', chunk_size=2048):
        """
        Reads from the socket until the delimiter is found.
        Returns the data *before* the delimiter.
        """
        while True:
            # 1. Check if the delimiter is already in the buffer
            index = self.buffer.find(delimiter)
            
            if index != -1:
                # Delimiter found!
                # Extract the message (up to the delimiter)
                message = self.buffer[:index]
                
                # Update the buffer to start *after* the delimiter
                self.buffer = self.buffer[index + len(delimiter):]
                return message
            
            # 2. If not found, read more data from the socket
            try:
                # Use b'' for Python 3, '' for Python 2 (though b'' works
                # in Py2 if you treat strings as byte-strings)
                chunk = self.sock.recv(chunk_size) 
            except socket.error as e:
                # Handle socket error (e.g., connection reset)
                raise Exception("Socket error during read: %s" % e)

            if not chunk:
                # EOF reached (connection closed)
                if self.buffer:
                    # Return any remaining data before closing
                    remaining = self.buffer
                    self.buffer = b''
                    return remaining
                # Nothing left to read
                return None 

            # Add the new chunk to the buffer
            self.buffer += chunk

# Python 2 Client
def send_to_python3(response_bytes):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        
        # Ensure we send the delimiter so the server knows we are done
        if not response_bytes.endswith('\n'):
            s.sendall(response_bytes + '\n')
        else:
            s.sendall(response_bytes)
            
        # You shouldn't need sleep if the logic is correct, 
        # but it doesn't hurt to leave it for now.
        time.sleep(1) 
        
        # 2. Receive the processed response
        reader = SocketReader(s)
        data = reader.read_until()
        
        s.close()
        print( "Client receive: ", data)
        return data
    
    except Exception as e: # Catch the specific error
        print( "Socket error details:", e)
        return None

