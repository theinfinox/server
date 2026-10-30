# Server Stats

Real-time telemetry and WebSocket server for monitoring server metrics (CPU load, RAM usage, temperature, uptime, and load averages).

## Architecture
- **Backend:** Node.js WebSocket server (`server.js`) streaming system metrics on port `3051`.
- **Frontend:** Responsive live dashboard (`index.html`) connecting to the WebSocket stream.

## Setup & Running
```bash
npm install
npm start
```

