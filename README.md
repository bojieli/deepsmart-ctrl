# Unofficial DeepSmart Controller

This project provides a Python script to control DeepSmart devices through their API. It allows you to turn devices on and off using command-line instructions.

## Prerequisites

- Python 3.10 or higher
- `pip` for installing dependencies

## Installation

1. Clone this repository or download the source code.

2. Install the required dependencies:
   ```
   pip install websocket-client requests pyyaml
   ```

3. Update `secrets.yaml` with your DeepSmart username (phone number) and password:
   ```yaml
   user:
     username: "your_phone_number"
     password: "your_password"
   ```

## Configuration

The `config.yaml` file contains the necessary configuration for the script to work. You shouldn't need to modify this unless the API endpoints change.

## Usage

To use the script, run it from the command line with the following syntax:

```
python deepsmart-ctrl.py <device_name> <action>
```

Where:
- `<device_name>` is the name of the device you want to control
- `<action>` is either "on" or "off"

For example:
```
python deepsmart-ctrl.py "玄关筒灯" on
```

If you run the script without arguments, it will display a list of available devices and usage instructions.

## Security Note

This script stores your DeepSmart credentials in the `secrets.yaml` file. Ensure this file is kept secure and not shared or committed to version control.

## Disclaimer

This is an unofficial tool and is not affiliated with or endorsed by DeepSmart. Use at your own risk.

## License

This project is licensed under the MIT License.