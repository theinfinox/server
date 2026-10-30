const WebSocket = require('ws');
const os = require('os');
const fs = require('fs'); // Added to read hardware files

// Start WebSocket server on port 8080
const wss = new WebSocket.Server({ port: 3051 });

console.log("WebSocket Server running on ws://localhost:3051");

// Helper function to calculate CPU load
function getCpuLoad() {
    const cpus = os.cpus();
    let totalIdle = 0, totalTick = 0;
    
    cpus.forEach(cpu => {
        for (let type in cpu.times) {
            totalTick += cpu.times[type];
        }
        totalIdle += cpu.times.idle;
    });
    
    return { idle: totalIdle / cpus.length, total: totalTick / cpus.length };
}

// Helper function to get CPU Temperature (Native Linux/ARM)
// Helper function to get CPU Temperature
function getCpuTemp() {
    try {
        // Reads the Intel x86_pkg_temp thermal zone
        const temp = fs.readFileSync('/sys/class/thermal/thermal_zone6/temp', 'utf8');
        return (parseInt(temp) / 1000).toFixed(1); // Converts 42000 to 42.0
    } catch (e) {
        return null;
    }
}

// Helper function to format system uptime
function formatUptime(seconds) {
    const d = Math.floor(seconds / (3600 * 24));
    const h = Math.floor(seconds % (3600 * 24) / 3600);
    const m = Math.floor(seconds % 3600 / 60);
    return `${d}d ${h}h ${m}m`;
}

let startMeasure = getCpuLoad();

// Handle Client Connections
wss.on('connection', (ws) => {
    console.log("New dashboard client connected.");

    // Send metrics every 1 second
    const interval = setInterval(() => {
        // 1. Calculate Real CPU %
        const endMeasure = getCpuLoad();
        const idleDifference = endMeasure.idle - startMeasure.idle;
        const totalDifference = endMeasure.total - startMeasure.total;
        const cpuPercentage = 100 - ~~(100 * idleDifference / totalDifference);
        startMeasure = endMeasure; // reset for next tick

        // 2. Calculate Real RAM %
        const totalMem = os.totalmem();
        const freeMem = os.freemem();
        const usedMem = totalMem - freeMem;
        const ramPercentage = (usedMem / totalMem) * 100;

        // 3. Package and Send
        const payload = {
            // Live dynamic metrics
            cpu: cpuPercentage,
            ram: ramPercentage,
            time: new Date().toISOString(),
            temp: getCpuTemp(),
            loadAvg: os.loadavg().map(load => load.toFixed(2)), // [1m, 5m, 15m]
            
            // Slower moving / Static OS metrics
            uptime: formatUptime(os.uptime()),
            osDetails: `${os.type()} ${os.release()}`, // e.g., "Linux 6.1.21-v8+"
            architecture: os.arch() // e.g., "arm64" or "x64"
        };

        // Only send if the connection is still open
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(payload));
        }
    }, 1000);

    // Clean up when client leaves
    ws.on('close', () => {
        clearInterval(interval);
        console.log("Client disconnected.");
    });
});
