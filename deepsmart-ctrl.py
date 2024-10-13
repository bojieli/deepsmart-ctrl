import websocket
import json
import struct
import requests
import hashlib
import yaml

class NetbeatService:
    def __init__(self, config):
        self.ws = None
        self.cust_id = None
        self.login_auth = None
        self.msg_no = 1
        self.config = config

    def connect(self):
        self.ws = websocket.create_connection(self.config['server']['uri'])

    def login(self):
        # Step 1: Get salt and sid
        url = self.config['server']['salt_url'] + self.config['user']['username'] + "/"
        headers = self.config['constants']['headers']
        response = requests.post(url, headers=headers)
        # Log the response
        print("Salt and SID response:")
        print(json.dumps(response.json(), indent=2))

        login_data = response.json()['data']
        salt = login_data['salt']
        sid = login_data['sid']
        code = login_data['code']

        # Step 2: Compute password
        def sha256(s):
            return hashlib.sha256(s.encode()).hexdigest()
        
        def md5(s):
            return hashlib.md5(s.encode()).hexdigest()
        
        password_hash = sha256(sha256(md5(self.config['user']['password'] + self.config['constants']['password_salt']) + salt) + code)

        # Step 3: Login
        login_url = self.config['server']['login_url']
        login_payload = {
            "username": self.config['user']['username'],
            "sid": sid,
            "password": password_hash
        }
        login_response = requests.post(login_url, headers=headers, json=login_payload)

        # Log login response
        print("Login response:")
        print(json.dumps(login_response.json(), indent=2))
        login_result = login_response.json()['data']

        self.cust_id = login_result['idStr']
        self.login_auth = login_result['auth']
        
        # Now use cust_id and login_auth for WebSocket connection
        login_msg = self.construct_login_message()
        print("Login message hex dump:")
        print(' '.join(f'{byte:02x}' for byte in login_msg))
        self.ws.send(login_msg)
        
        response = self.ws.recv()
        print("Login response hex dump:")
        self.print_hex_dump(response)

    def construct_login_message(self):
        start = self.config['message']['start_byte']
        version = self.config['message']['version']
        msg_type = 0x01  # LOGIN
        login_type = [self.config['message']['login_type']]
        
        cust_id_bytes = self.split_bytes(self.cust_id, 8)
        auth_bytes = self.split_auth(self.login_auth)
        body = login_type + list(cust_id_bytes) + list(auth_bytes)
        
        checksum = self.calc_checksum(body)
        body += checksum + bytes([self.config['message']['end_byte']])
        
        msg_length = len(body)
        header = struct.pack('>BHB', start, msg_length, version)
        
        msg_no = self.next_message_num()
        
        msg = header + struct.pack('>H', msg_no) + bytes([msg_type]) + bytes(body)
        
        # Adjust length bytes after constructing full message
        msg = bytearray(msg)
        msg[1] = msg_length & 0xFF
        msg[2] = (msg_length >> 8) & 0xFF
        msg = bytes(msg)

        return msg + checksum + bytes([self.config['message']['end_byte']])

    def send_cmd(self, cmd):
        binary_cmd = self.build_send_cmd(cmd)
        message = self.construct_send_message(binary_cmd, cmd['chat_id'], cmd['to_cust_id'])
        self.ws.send(message)
        
        # Log hex dump of sent message
        print("Sent message hex dump:")
        self.print_hex_dump(message)
        
        response = self.ws.recv()

        # Log hex dump of response
        print("Response hex dump:")
        self.print_hex_dump(response)

    def build_data(self, cmd):
        result = []
        target_type = self.split_int16(0)
        addr = self.split_int16(cmd['addr'])
        data_type = cmd['data_type']
        data = self.split_4bytes(cmd['data'])
        time_wait = self.split_int16(cmd['time_wait'])
        
        result.extend(target_type)
        result.extend(addr)
        result.extend([data_type])
        result.extend(data)
        result.extend(time_wait)
        
        return bytes(result)

    def build_send_cmd(self, cmd):
        magic_header = bytes([0x68, 0x01])
        length = bytes([0, 0])
        afn = self.split_int16(cmd['afn'])
        data = self.build_data(cmd)
        if data is None:
            print("data is empty")
            return None
        
        content = magic_header + length + afn + data
        data_len = len(data)
        content = bytearray(content)
        content[3] = data_len >> 8
        content[2] = data_len & 0xFF
        
        total = sum(content[1:])
        checksum = self.split_int16(total)[0]
        
        content.extend([checksum, 0x16])
        
        return bytes(content)

    def construct_send_message(self, binary_cmd, chat_id, to_cust_id):
        start = 0x02
        version = 0x01
        msg_type = 0x03 # cmd

        chat_id_bytes = self.split_bytes(chat_id, 8)
        from_cust_id_bytes = self.split_bytes(self.cust_id, 8)
        to_cust_id_bytes = self.split_bytes(to_cust_id, 8)
        
        msg_expire_time = self.split_int32(0)
        chat_type = bytes([0x02])
        login_type = bytes([0x05])
        
        content_len = self.split_int16(len(binary_cmd))
        is_binary = bytes([0x01])
        
        body = (msg_expire_time + chat_type + login_type + chat_id_bytes + 
                from_cust_id_bytes + to_cust_id_bytes + content_len + is_binary + binary_cmd)
        
        checksum = self.calc_checksum(body)
        body += checksum + b'\x03'
        
        msg_length = len(body)
        header = struct.pack('>BHB', start, msg_length, version)
        
        msg_no = self.next_message_num()
        msg_no_bytes = self.split_int16(msg_no)
        
        msg = header + msg_no_bytes + bytes([msg_type]) + body
        
        # Adjust length bytes after constructing full message
        msg = bytearray(msg)
        msg[1] = msg_length & 0xFF
        msg[2] = (msg_length >> 8) & 0xFF
        
        return bytes(msg)

    @staticmethod
    def split_bytes(value, byte_num):
        if isinstance(value, str):
            # Ensure even length
            if len(value) % 2 != 0:
                value = '0' + value
            
            # Convert hex string to list of integers
            hex_list = [int(value[i:i+2], 16) for i in range(0, len(value), 2)]
            
            # Reverse the list
            hex_list.reverse()
            
            # Pad with zeros if necessary
            while len(hex_list) < byte_num:
                hex_list.append(0)
            
            # Truncate if longer than byte_num
            hex_list = hex_list[:byte_num]
            
            return bytes(hex_list)
        else:
            # If value is already an int, use the original method
            return value.to_bytes(byte_num, 'little')

    @staticmethod
    def split_auth(auth):
        auth_bytes = auth.encode('utf-8')
        return auth_bytes.ljust(32, b'\0')

    @staticmethod
    def split_int32(value):
        return struct.pack('<I', value)

    @staticmethod
    def split_int16(value):
        return struct.pack('<H', value)

    @staticmethod
    def split_4bytes(value):
        return struct.pack('<I', value)

    @staticmethod
    def calc_checksum(data):
        checksum = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                checksum ^= (data[i] << 8) | data[i+1]
            else:
                checksum ^= data[i] << 8
        return struct.pack('>H', checksum)

    def next_message_num(self):
        msg_no = self.msg_no
        self.msg_no += 1
        return msg_no

    @staticmethod
    def parse_long_long(data):
        return int.from_bytes(data, byteorder='little')

    @staticmethod
    def cal_status(high, low):
        return (high << 8) | low

    @staticmethod
    def parse_string(data):
        return data.decode('utf-8')

    @staticmethod
    def print_hex_dump(data):
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_dump = ' '.join(f'{byte:02x}' for byte in chunk)
            print(f'{i:04x}: {hex_dump:<48}')

def send_command(config):
    netbeat = NetbeatService(config)
    netbeat.connect()
    netbeat.login()
    
    cmd = config['command']
    result = netbeat.send_cmd(cmd)
    print(f"Command result: {result}")

if __name__ == "__main__":
    with open('config.yaml', 'r') as file:
        config = yaml.safe_load(file)
    
    send_command(config)
