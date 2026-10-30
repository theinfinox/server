const WebSocket = require('ws');
const os = require('os');
const fs = require('fs');
const path = require('path');

let pm2 = null;
try {
    pm2 = require('pm2');
} catch (e) {
    console.warn('[PM2] pm2 package not found, running in standalone mode.');
}

const PORT = process.env.PORT || 3051;
const CONFIG_FILE = path.join(__dirname, 'pm2-config.json');

// Start WebSocket server
const wss = new WebSocket.Server({ port: PORT });
console.log(`WebSocket Server running on ws://0.0.0.0:${PORT}`);

// -------------------------------------------------------------
// 1. THERMAL SENSOR AUTO-RESOLVER
// -------------------------------------------------------------
let cachedThermalSensor = undefined; // undefined: not scanned yet, null: not found
let cachedSensorType = null;

function resolveThermalSensor() {
    if (cachedThermalSensor !== undefined) {
        return cachedThermalSensor;
    }

    const priorityTypes = ['x86_pkg_temp', 'cpu-thermal', 'soc-thermal', 'coretemp', 'k10temp', 'acpitz'];
    const thermalBase = '/sys/class/thermal';

    try {
        if (fs.existsSync(thermalBase)) {
            const entries = fs.readdirSync(thermalBase).filter(name => name.startsWith('thermal_zone'));
            const candidates = [];

            for (const zone of entries) {
                const typePath = path.join(thermalBase, zone, 'type');
                const tempPath = path.join(thermalBase, zone, 'temp');
                if (fs.existsSync(typePath) && fs.existsSync(tempPath)) {
                    try {
                        const type = fs.readFileSync(typePath, 'utf8').trim().toLowerCase();
                        candidates.push({ type, tempPath });
                    } catch (e) {}
                }
            }

            // Find by priority
            for (const prio of priorityTypes) {
                const match = candidates.find(c => c.type.includes(prio));
                if (match) {
                    cachedThermalSensor = match.tempPath;
                    cachedSensorType = match.type;
                    console.log(`[Thermal] Auto-resolved primary CPU sensor: ${match.tempPath} (${match.type})`);
                    return cachedThermalSensor;
                }
            }

            // Fallback to first available candidate
            if (candidates.length > 0) {
                cachedThermalSensor = candidates[0].tempPath;
                cachedSensorType = candidates[0].type;
                console.log(`[Thermal] Fallback thermal sensor: ${candidates[0].tempPath} (${candidates[0].type})`);
                return cachedThermalSensor;
            }
        }
    } catch (err) {
        console.warn('[Thermal] Sensor scan warning:', err.message);
    }

    cachedThermalSensor = null;
    cachedSensorType = null;
    return null;
}

function getCpuTemp() {
    try {
        const sensorPath = resolveThermalSensor();
        if (!sensorPath) return null;
        const raw = fs.readFileSync(sensorPath, 'utf8').trim();
        const val = parseFloat(raw);
        if (isNaN(val)) return null;
        const tempC = val > 1000 ? val / 1000 : val;
        return tempC.toFixed(1);
    } catch (e) {
        return null;
    }
}

// -------------------------------------------------------------
// 2. ACCURATE SYSTEM METRICS (CPU, MEMORY, STORAGE)
// -------------------------------------------------------------
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

function getMemoryMetrics() {
    try {
        if (process.platform === 'linux' && fs.existsSync('/proc/meminfo')) {
            const content = fs.readFileSync('/proc/meminfo', 'utf8');
            let memTotalKb = null;
            let memAvailKb = null;

            for (const line of content.split('\n')) {
                if (line.startsWith('MemTotal:')) {
                    memTotalKb = parseInt(line.replace(/[^0-9]/g, ''), 10);
                } else if (line.startsWith('MemAvailable:')) {
                    memAvailKb = parseInt(line.replace(/[^0-9]/g, ''), 10);
                }
                if (memTotalKb !== null && memAvailKb !== null) break;
            }

            if (memTotalKb && memAvailKb !== null) {
                const usedKb = memTotalKb - memAvailKb;
                const percent = (usedKb / memTotalKb) * 100;
                return {
                    percent: Math.min(100, Math.max(0, percent)),
                    totalMB: Math.round(memTotalKb / 1024),
                    usedMB: Math.round(usedKb / 1024),
                    availableMB: Math.round(memAvailKb / 1024)
                };
            }
        }
    } catch (e) {}

    // Fallback for non-Linux or on error
    const total = os.totalmem();
    const free = os.freemem();
    const used = total - free;
    return {
        percent: total > 0 ? (used / total) * 100 : 0,
        totalMB: Math.round(total / (1024 * 1024)),
        usedMB: Math.round(used / (1024 * 1024)),
        availableMB: Math.round(free / (1024 * 1024))
    };
}

function getDiskMetrics() {
    try {
        if (typeof fs.statfsSync === 'function') {
            const stat = fs.statfsSync('/');
            const totalBytes = stat.bsize * stat.blocks;
            const freeBytes = stat.bsize * stat.bavail;
            const usedBytes = totalBytes - freeBytes;
            if (totalBytes > 0) {
                const usedPercent = (usedBytes / totalBytes) * 100;
                return {
                    totalGB: parseFloat((totalBytes / 1e9).toFixed(1)),
                    usedGB: parseFloat((usedBytes / 1e9).toFixed(1)),
                    freeGB: parseFloat((freeBytes / 1e9).toFixed(1)),
                    usedPercent: parseFloat(usedPercent.toFixed(1))
                };
            }
        }
    } catch (e) {}
    return null;
}

function formatUptime(seconds) {
    const d = Math.floor(seconds / (3600 * 24));
    const h = Math.floor((seconds % (3600 * 24)) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return `${d}d ${h}h ${m}m`;
}

function formatDuration(ms) {
    if (!ms || ms <= 0) return '0m';
    const totalSeconds = Math.floor(ms / 1000);
    const days = Math.floor(totalSeconds / 86400);
    const hours = Math.floor((totalSeconds % 86400) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);

    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
}

// -------------------------------------------------------------
// 3. PM2 CONFIG MANAGER (AUTO-POPULATE & PRESERVE USER CHOICE)
// -------------------------------------------------------------
function syncPm2Config(discoveredProcessNames) {
    let config = {
        version: "1.0",
        description: "User-controlled visibility for PM2 process telemetry on the dashboard",
        processes: {}
    };

    try {
        if (fs.existsSync(CONFIG_FILE)) {
            const raw = fs.readFileSync(CONFIG_FILE, 'utf8');
            const parsed = JSON.parse(raw);
            if (parsed && typeof parsed.processes === 'object') {
                config = parsed;
            }
        }
    } catch (err) {
        console.warn('[PM2 Config] Failed to read config file, keeping defaults:', err.message);
    }

    if (!config.processes) config.processes = {};

    let hasChanges = false;
    for (const name of discoveredProcessNames) {
        if (name && config.processes[name] === undefined) {
            // New process discovered! Auto-populate:
            // Hide host monitoring process 'server-stats' by default; all others default to visible
            const isSelf = name.toLowerCase() === 'server-stats';
            config.processes[name] = {
                visible: !isSelf,
                addedAt: new Date().toISOString()
            };
            if (isSelf) {
                config.processes[name].note = "Host server process (hidden by default)";
            }
            hasChanges = true;
            console.log(`[PM2 Config] Auto-populated new process: "${name}" (visible: ${!isSelf})`);
        }
    }

    if (hasChanges) {
        try {
            const tempFile = `${CONFIG_FILE}.tmp`;
            fs.writeFileSync(tempFile, JSON.stringify(config, null, 2), 'utf8');
            fs.renameSync(tempFile, CONFIG_FILE);
        } catch (writeErr) {
            console.error('[PM2 Config] Failed to atomically write config file:', writeErr.message);
        }
    }

    // Build fast lookup map for visibility
    const visibilityMap = {};
    for (const [key, val] of Object.entries(config.processes)) {
        if (typeof val === 'boolean') {
            visibilityMap[key] = val;
        } else if (val && typeof val.visible === 'boolean') {
            visibilityMap[key] = val.visible;
        } else {
            visibilityMap[key] = true;
        }
    }
    return visibilityMap;
}

// -------------------------------------------------------------
// 4. DECOUPLED PM2 HEALTH WORKER
// -------------------------------------------------------------
let pm2State = {
    available: false,
    summary: { total: 0, online: 0, stopped: 0, errored: 0 },
    processes: []
};

let isPm2Connected = false;
let isPm2Polling = false;

function connectAndPollPm2() {
    if (!pm2) {
        pm2State.available = false;
        return;
    }

    if (!isPm2Connected) {
        pm2.connect(true, (err) => {
            if (err) {
                isPm2Connected = false;
                pm2State.available = false;
                return;
            }
            isPm2Connected = true;
            pm2State.available = true;
            pollPm2List();
        });
    } else {
        pollPm2List();
    }
}

function pollPm2List() {
    if (isPm2Polling || !isPm2Connected) return;
    isPm2Polling = true;

    pm2.list((err, list) => {
        isPm2Polling = false;
        if (err) {
            console.warn('[PM2] List error, resetting connection:', err.message);
            isPm2Connected = false;
            pm2State.available = false;
            return;
        }

        try {
            const now = Date.now();
            const names = list.map(p => p.name).filter(Boolean);
            const visibilityMap = syncPm2Config(names);

            const filteredProcesses = [];
            let total = 0, online = 0, stopped = 0, errored = 0;

            for (const p of list) {
                const name = p.name || 'unnamed';
                const isVisible = visibilityMap[name] !== false; // defaults to true unless explicitly false

                if (!isVisible) {
                    continue; // Skipped per user configuration
                }

                total++;
                const status = (p.pm2_env && p.pm2_env.status) ? p.pm2_env.status.toLowerCase() : 'unknown';
                if (status === 'online') online++;
                else if (status === 'stopped') stopped++;
                else if (status === 'errored') errored++;

                const restarts = (p.pm2_env && p.pm2_env.restart_time) || 0;
                const memoryBytes = (p.monit && p.monit.memory) || 0;
                const cpuPercent = (p.monit && typeof p.monit.cpu === 'number') ? p.monit.cpu : 0;
                const uptimeMs = (p.pm2_env && p.pm2_env.pm_uptime) ? (now - p.pm2_env.pm_uptime) : 0;

                filteredProcesses.push({
                    id: p.pm_id !== undefined ? p.pm_id : null,
                    name: name,
                    status: status,
                    uptime: formatDuration(uptimeMs),
                    uptimeMs: (p.pm2_env && p.pm2_env.pm_uptime) || 0,
                    restarts: restarts,
                    restartAlert: restarts > 10,
                    memoryMB: parseFloat((memoryBytes / (1024 * 1024)).toFixed(1)),
                    cpu: parseFloat(cpuPercent.toFixed(1)),
                    mode: (p.pm2_env && p.pm2_env.exec_mode) || 'fork',
                    pid: p.pid || null,
                    nodeVersion: (p.pm2_env && p.pm2_env.node_version) || null
                });
            }

            // Sort: online first, then by name
            filteredProcesses.sort((a, b) => {
                if (a.status === 'online' && b.status !== 'online') return -1;
                if (a.status !== 'online' && b.status === 'online') return 1;
                return a.name.localeCompare(b.name);
            });

            pm2State = {
                available: true,
                summary: { total, online, stopped, errored },
                processes: filteredProcesses
            };
        } catch (procErr) {
            console.error('[PM2] Processing error:', procErr.message);
        }
    });
}

// Poll PM2 every 2.5 seconds in background
if (pm2) {
    connectAndPollPm2();
    setInterval(connectAndPollPm2, 2500);
}

// -------------------------------------------------------------
// 5. CLIENT CONNECTION & 1-SECOND TELEMETRY BROADCAST
// -------------------------------------------------------------
let startMeasure = getCpuLoad();

wss.on('connection', (ws) => {
    console.log("New dashboard client connected.");

    const interval = setInterval(() => {
        // 1. Calculate Real CPU %
        const endMeasure = getCpuLoad();
        const idleDifference = endMeasure.idle - startMeasure.idle;
        const totalDifference = endMeasure.total - startMeasure.total;
        const cpuPercentage = totalDifference > 0 
            ? Math.min(100, Math.max(0, 100 - ~~(100 * idleDifference / totalDifference)))
            : 0;
        startMeasure = endMeasure;

        // 2. Memory & Disk
        const mem = getMemoryMetrics();
        const disk = getDiskMetrics();

        // 3. Compose Payload (100% backward-compatible + additive fields)
        const payload = {
            // Backward-compatible original keys
            cpu: cpuPercentage,
            ram: parseFloat(mem.percent.toFixed(1)),
            time: new Date().toISOString(),
            temp: getCpuTemp(),
            loadAvg: os.loadavg().map(load => load.toFixed(2)),
            uptime: formatUptime(os.uptime()),
            osDetails: `${os.type()} ${os.release()}`,
            architecture: os.arch(),

            // Additive hardware & environment metrics
            hostname: os.hostname(),
            tempSensor: cachedSensorType,
            ramDetails: {
                totalMB: mem.totalMB,
                usedMB: mem.usedMB,
                availableMB: mem.availableMB
            },
            disk: disk,

            // PM2 health & process matrix
            pm2: pm2State
        };

        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(payload));
        }
    }, 1000);

    ws.on('close', () => {
        clearInterval(interval);
        console.log("Client disconnected.");
    });

    ws.on('error', (err) => {
        clearInterval(interval);
        console.warn("Client socket error:", err.message);
    });
});
