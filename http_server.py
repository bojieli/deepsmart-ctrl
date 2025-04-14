import yaml
import json
from flask import Flask, jsonify, request
from deepsmart_ctrl import NetbeatService
from datetime import datetime

app = Flask(__name__)

# Global NetbeatService instance
netbeat = None

# Command history tracking
command_history = []

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """List all available devices"""
    try:
        device_info = netbeat.get_device_info()
        device_map = netbeat.parse_device_info(device_info)
        devices = []
        
        for name, details in device_map.items():
            devices.append({
                'name': name,
                'addr': details['addr'],
                'to_cust_id': details['to_cust_id']
            })
            
        return jsonify({
            'status': 'success',
            'devices': devices
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/devices/<device_name>', methods=['GET'])
def get_device_details(device_name):
    """Get details of a specific device"""
    try:
        device_info = netbeat.get_device_info()
        device_map = netbeat.parse_device_info(device_info)
        
        if device_name not in device_map:
            return jsonify({
                'status': 'error',
                'message': f'Device "{device_name}" not found'
            }), 404
            
        details = device_map[device_name]
        
        return jsonify({
            'status': 'success',
            'device': {
                'name': device_name,
                'addr': details['addr'],
                'to_cust_id': details['to_cust_id'],
                'on_value': details['on_value'],
                'off_value': details['off_value']
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/devices/control', methods=['POST'])
def control_device():
    """Control a device (turn on/off)"""
    try:
        data = request.json
        if not data or 'device_name' not in data or 'action' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Missing device_name or action in request'
            }), 400
            
        device_name = data['device_name']
        action = data['action']
        
        if action not in ['on', 'off']:
            return jsonify({
                'status': 'error',
                'message': 'Invalid action. Use "on" or "off"'
            }), 400
            
        # Get device info
        device_info = netbeat.get_device_info()
        device_map = netbeat.parse_device_info(device_info)
        
        if device_name not in device_map:
            return jsonify({
                'status': 'error',
                'message': f'Device "{device_name}" not found'
            }), 404
            
        # Prepare command
        device = device_map[device_name]
        cmd = app.config['deepsmart_config']['command'].copy()
        cmd['addr'] = device['addr']
        cmd['to_cust_id'] = device['to_cust_id']
        cmd['data'] = int(device['on_value']) if action == 'on' else int(device['off_value'])
        
        # Send command
        netbeat.send_cmd(cmd)
        
        # Record command in history
        command_history.append({
            'timestamp': datetime.now().isoformat(),
            'device_name': device_name,
            'action': action,
            'addr': device['addr'],
            'to_cust_id': device['to_cust_id'],
            'data': int(device['on_value']) if action == 'on' else int(device['off_value'])
        })
        
        return jsonify({
            'status': 'success',
            'message': f'Device "{device_name}" turned {action}'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/refresh', methods=['POST'])
def refresh_connection():
    """Reconnect to the DeepSmart service"""
    try:
        init_service()
        return jsonify({
            'status': 'success',
            'message': 'Successfully reconnected to DeepSmart service'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to reconnect: {str(e)}'
        }), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get server and connection status"""
    try:
        # Check if we can get device info to verify connection is active
        netbeat.get_home_info()
        
        return jsonify({
            'status': 'success',
            'server': {
                'connected': True,
                'cust_id': netbeat.cust_id,
                'chat_id': netbeat.chat_id
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'server': {
                'connected': False,
                'error': str(e)
            }
        }), 500

@app.route('/api/history', methods=['GET'])
def get_command_history():
    """Get the history of commands executed"""
    try:
        return jsonify({
            'status': 'success',
            'history': command_history
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/history/clear', methods=['POST'])
def clear_command_history():
    """Clear the command history"""
    try:
        global command_history
        command_history = []
        return jsonify({
            'status': 'success',
            'message': 'Command history cleared'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def init_service():
    """Initialize the NetbeatService and login"""
    global netbeat
    
    with open('config.yaml', 'r') as file:
        config = yaml.safe_load(file)
    
    with open('secrets.yaml', 'r') as file:
        secrets = yaml.safe_load(file)
    
    # Store config for later use in routes
    app.config['deepsmart_config'] = config
    
    # Initialize and login to the service
    netbeat = NetbeatService(config, secrets)
    netbeat.connect()
    netbeat.login()
    print("Successfully logged in to DeepSmart service")

if __name__ == '__main__':
    # Initialize service before starting the server
    init_service()
    
    # Show the list of all devices at startup
    try:
        device_info = netbeat.get_device_info()
        device_map = netbeat.parse_device_info(device_info)
        
        print("\nAvailable devices:")
        for name in device_map.keys():
            print(f"  - {name}")
        print()
    except Exception as e:
        print(f"Error retrieving device list: {str(e)}")
    
    # Start the HTTP server
    app.run(host='0.0.0.0', port=5000, debug=True) 