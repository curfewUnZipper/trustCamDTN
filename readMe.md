| Node / Component               | Runs Where?              | Role                                          |
| ------------------------------ | ------------------------ | --------------------------------------------- |
| **1. Edge Device**             | ESP32-CAM                | Capture image → encrypt → send                |
| **2. DTN Gateway**             | Raspberry Pi / Laptop    | Temporary storage + Delay-Tolerant forwarding |
| **3. Main Application Server** | Flask/FastAPI backend    | Stores encrypted data, verifies provenance    |
| **4. Viewer Client**           | Browser / Desktop script | Decrypts & verifies authenticity              |



How to run for the first time:

unzip trustcam_flask_backend.zip
cd trustcam_flask_backend
python -m venv trust
cd trust/scripts && activate && cd ../..
pip install -r requirements.txt
python app.py



test routes and json:
| Endpoint             | Method | Description                            |
| -------------------- | ------ | -------------------------------------- |
| `/`                  | GET    | Health check                           |
| `/receive`           | POST   | Upload encrypted bundle from ESP32/DTN |
| `/images`            | GET    | List stored images                     |
| `/images/<filename>` | GET    | Download image                         |
| `/log`               | GET    | View transparency log                  |
| `/log/verify`        | GET    | Verify hash-chain integrity            |



POST json data:

1. /receive
{
  "device_id": "ESP32_CAM_01",
  "timestamp": "2025-11-29T14:20:00Z",
  "firmware_version": "2.1",
  "dtn_mode": "enabled"
}


testing metadata:
{
  "device_id": "TEST_DEVICE_01",
  "timestamp": "2025-11-29T15:00:00Z",
  "firmware_version": "debug"
}

Body/Form --files:
| Key         | Type | Value                       |
| ----------- | ---- | --------------------------- |
| `data`      | File | `encrypted.bin`             |
| `signature` | File | `signature.bin`             |
| `metadata`  | Text | (paste metadata JSON above) |


Expected form-data fields:
data → run testing/encryptor to generate encrypted payload
signature → raw 64-byte ECDSA signature over SHA-256 hash of the encrypted data
metadata → JSON string containing device information and timestamp


testing with curl:
(trust) C:\Users\cryin\Work\trustCamDTN>curl -X POST http://localhost:5000/receive -F "data=@./testing/encrypted.bin" -F "signature=@./testing/signature.bin" -F "metadata={\"device_id\":\"TEST_DEVICE_01\",\"timestamp\":\"2025-11-29T15:00:00Z\"}"


response:
{
  "file": "TEST_DEVICE_01_20251129_121042_622803.jpg",
  "log_entry": {
    "device_id": "TEST_DEVICE_01",
    "device_timestamp": "2025-11-29T15:00:00Z",
    "event_hash": "18385cb91e9535a5c06bf754aff0ecf6f1620292a106960fa09ac4646edbf0bc",
    "index": 0,
    "metadata": {
      "device_id": "TEST_DEVICE_01",
      "timestamp": "2025-11-29T15:00:00Z"
    },
    "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "timestamp": "2025-11-29T12:10:42.619678Z"
  },
  "message": "Bundle received and processed",
  "signature_ok": true,
  "status": "ok"
}


curl http://localhost:5000/images/TEST_DEVICE_01_20251129_121042_622803.jpg -o ./testing/received.jpg
