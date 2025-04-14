# DeepSmart HTTP Server

This is an HTTP API server for controlling DeepSmart devices. It wraps the existing DeepSmart control interface with a RESTful API.

## Installation

1. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Ensure that `config.yaml` and `secrets.yaml` are properly configured.

## Usage

Start the server:
```
python http_server.py
```

The server will:
1. Connect to the DeepSmart service
2. Login using the credentials in `secrets.yaml`
3. Display a list of all available devices
4. Start an HTTP server on port 5000

## API Endpoints

### List all devices

```
GET /api/devices
```

Example response:
```json
{
  "status": "success",
  "devices": [
    {
      "name": "Device 1",
      "addr": 12345,
      "to_cust_id": "abcdef"
    },
    {
      "name": "Device 2",
      "addr": 67890,
      "to_cust_id": "ghijkl"
    }
  ]
}
```

### Get details of a specific device

```
GET /api/devices/<device_name>
```

Example response:
```json
{
  "status": "success",
  "device": {
    "name": "Device 1",
    "addr": 12345,
    "to_cust_id": "abcdef",
    "on_value": "1",
    "off_value": "0"
  }
}
```

### Control a device

```
POST /api/devices/control
```

Request body:
```json
{
  "device_name": "Device 1",
  "action": "on"  // or "off"
}
```

Example response:
```json
{
  "status": "success",
  "message": "Device \"Device 1\" turned on"
}
```

### Get command history

```
GET /api/history
```

Example response:
```json
{
  "status": "success",
  "history": [
    {
      "timestamp": "2023-09-15T14:30:45.123456",
      "device_name": "Device 1",
      "action": "on",
      "addr": 12345,
      "to_cust_id": "abcdef",
      "data": 1
    },
    {
      "timestamp": "2023-09-15T14:35:12.654321",
      "device_name": "Device 2",
      "action": "off",
      "addr": 67890,
      "to_cust_id": "ghijkl",
      "data": 0
    }
  ]
}
```

### Clear command history

```
POST /api/history/clear
```

Example response:
```json
{
  "status": "success",
  "message": "Command history cleared"
}
```

### Check server status

```
GET /api/status
```

Example response:
```json
{
  "status": "success",
  "server": {
    "connected": true,
    "cust_id": "12345678",
    "chat_id": "abcdefgh"
  }
}
```

### Refresh connection

```
POST /api/refresh
```

Example response:
```json
{
  "status": "success",
  "message": "Successfully reconnected to DeepSmart service"
}
```

## Error Handling

All API errors will return with an appropriate HTTP status code and a JSON response with details:

```json
{
  "status": "error",
  "message": "Error details here"
}
``` 