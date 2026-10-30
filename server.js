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
const MAX_TOTAL_CLIENTS = 100;
const MAX_CLIENTS_PER_IP = 10;

// Allowed Origins (Domain Protection against Cross-Site Hijacking)
const ALLOWED_ORIGIN_PATTERNS = [
    /^https?:\/\/info\.govindsr\.me$/i,
    /^https?:\/\/govindsr\.me$/i,
    /^https?:\/\/serverws\.govindsr\.me$/i,
    /^https?:\/\/.*\.pages\.dev$/i,
    /^https?:\/\/localhost(:\d+)?$/i,
    /^https?:\/\/127\.0\.0\.1(:\d+)?$/i,
    /^https?:\/\/192\.168\.\d+\.\d+(:\d+)?$/i,
    /^https?:\/\/10\.\d+\.\d+\.\d+(:\d+)?$/i,
    /^https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+(:\d+)?$/i
];

function getClientIp(req) {
    const forwarded = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.socket ? req.socket.remoteAddress : 'unknown';
}

function verifyClient(info, callback) {
    const origin = info.origin || info.req.headers.origin;

    // 1. Origin verification (if Origin header present)
    if (origin) {
        const isAllowed = ALLOWED_ORIGIN_PATTERNS.some(pattern => pattern.test(origin));
        if (!isAllowed) {
            console.warn(`[Security] Rejected WebSocket connection from unauthorized origin: ${origin}`);
            return callback(false, 403, 'Forbidden: Unauthorized Origin');
        }
    }

    // 2. Global connection limit
    if (wss.clients && wss.clients.size >= MAX_TOTAL_CLIENTS) {
        console.warn(`[Security] Connection rejected: Global limit reached (${MAX_TOTAL_CLIENTS})`);
        return callback(false, 503, 'Service Unavailable: Server at capacity');
    }

    // 3. Per-IP connection limit
    const clientIp = getClientIp(info.req);
    let ipCount = 0;
    if (wss.clients) {
        for (const client of wss.clients) {
            if (client.clientIp === clientIp && client.readyState === WebSocket.OPEN) {
                ipCount++;
            }
        }
    }

    if (ipCount >= MAX_CLIENTS_PER_IP) {
        console.warn(`[Security] Connection rejected: Too many connections from IP ${clientIp}`);
        return callback(false, 429, 'Too Many Requests: Connection limit per IP exceeded');
    }

    callback(true);
}

// Start WebSocket server with DoS protections
const wss = new WebSocket.Server({
    port: PORT,
    maxPayload: 1024, // 1 KB max payload protects against buffer overflow attacks
    verifyClient: verifyClient
});

console.log(`[Security] WebSocket Server running on ws://0.0.0.0:${PORT} with Origin whitelisting & DoS guard`);

// -------------------------------------------------------------
// 1. HARDWARE INFO CACHED AT STARTUP (ZERO TICK OVERHEAD)
// -------------------------------------------------------------
const CPU_MODEL = (os.cpus()[0] && os.cpus()[0].model) || 'x86_64 Processor';
const CPU_CORES = os.cpus().length || 1;

// -------------------------------------------------------------
// 2. THERMAL SENSOR AUTO-RESOLVER & MULTI-ZONE INSPECTOR
// -------------------------------------------------------------
let cachedThermalSensor = undefined;

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
                        const type = fs.readFileSync(typePath, 'utf8').trim();
                        candidates.push({ type, tempPath, zone });
                    } catch (e) {}
                }
            }

            for (const prio of priorityTypes) {
                const match = candidates.find(c => c.type.toLowerCase().includes(prio));
                if (match) {
                    cachedThermalSensor = match;
                    console.log(`[Thermal] Auto-resolved primary CPU sensor: ${match.tempPath} (${match.type})`);
                    return cachedThermalSensor;
                }
            }

            if (candidates.length > 0) {
                cachedThermalSensor = candidates[0];
                console.log(`[Thermal] Fallback thermal sensor selected: ${cachedThermalSensor.tempPath} (${cachedThermalSensor.type})`);
                return cachedThermalSensor;
            }
        }
    } catch (err) {}

    cachedThermalSensor = null;
    return null;
}

function getCpuTemp() {
    try {
        const sensor = resolveThermalSensor();
        if (!sensor) return { temp: null, type: 'UNKNOWN' };
        const raw = fs.readFileSync(sensor.tempPath, 'utf8').trim();
        const val = parseFloat(raw);
        if (isNaN(val)) return { temp: null, type: sensor.type };
        const tempC = val > 1000 ? val / 1000 : val;
        return { temp: tempC.toFixed(1), type: sensor.type };
    } catch (e) {
        return { temp: null, type: 'UNKNOWN' };
    }
}

function getAllThermalSensors() {
    const thermalBase = '/sys/class/thermal';
    const list = [];
    try {
        if (fs.existsSync(thermalBase)) {
            const entries = fs.readdirSync(thermalBase).filter(name => name.startsWith('thermal_zone'));
            for (const zone of entries) {
                const typePath = path.join(thermalBase, zone, 'type');
                const tempPath = path.join(thermalBase, zone, 'temp');
                if (fs.existsSync(typePath) && fs.existsSync(tempPath)) {
                    try {
                        const type = fs.readFileSync(typePath, 'utf8').trim();
                        const raw = fs.readFileSync(tempPath, 'utf8').trim();
                        const val = parseFloat(raw);
                        if (!isNaN(val)) {
                            const tempC = val > 1000 ? val / 1000 : val;
                            list.push({ zone, type, tempC: tempC.toFixed(1) });
                        }
                    } catch (e) {}
                }
            }
        }
    } catch (e) {}
    return list;
}

// -------------------------------------------------------------
// 3. ACCURATE SYSTEM & HARDWARE METRICS
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
            let memFreeKb = null;
            let buffersKb = 0;
            let cachedKb = 0;

            for (const line of content.split('\n')) {
                if (line.startsWith('MemTotal:')) {
                    memTotalKb = parseInt(line.replace(/[^0-9]/g, ''), 10);
                } else if (line.startsWith('MemAvailable:')) {
                    memAvailKb = parseInt(line.replace(/[^0-9]/g, ''), 10);
                } else if (line.startsWith('MemFree:')) {
                    memFreeKb = parseInt(line.replace(/[^0-9]/g, ''), 10);
                } else if (line.startsWith('Buffers:')) {
                    buffersKb = parseInt(line.replace(/[^0-9]/g, ''), 10);
                } else if (line.startsWith('Cached:')) {
                    cachedKb = parseInt(line.replace(/[^0-9]/g, ''), 10);
                }
            }

            if (memTotalKb && memAvailKb !== null) {
                const usedKb = memTotalKb - memAvailKb;
                const percent = (usedKb / memTotalKb) * 100;
                return {
                    percent: Math.min(100, Math.max(0, percent)),
                    totalMB: Math.round(memTotalKb / 1024),
                    usedMB: Math.round(usedKb / 1024),
                    availableMB: Math.round(memAvailKb / 1024),
                    freeMB: memFreeKb !== null ? Math.round(memFreeKb / 1024) : 0,
                    buffersMB: Math.round(buffersKb / 1024),
                    cachedMB: Math.round(cachedKb / 1024)
                };
            }
        }
    } catch (e) {}

    const total = os.totalmem();
    const free = os.freemem();
    const used = total - free;
    return {
        percent: total > 0 ? (used / total) * 100 : 0,
        totalMB: Math.round(total / (1024 * 1024)),
        usedMB: Math.round(used / (1024 * 1024)),
        availableMB: Math.round(free / (1024 * 1024)),
        freeMB: Math.round(free / (1024 * 1024)),
        buffersMB: 0,
        cachedMB: 0
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
                    totalGB: Math.round(totalBytes / 1e9),
                    usedGB: Math.round(usedBytes / 1e9),
                    usedPercent: parseFloat(usedPercent.toFixed(1))
                };
            }
        }
    } catch (e) {}
    return null;
}

// -------------------------------------------------------------
// 4. LIVE NETWORK THROUGHPUT ENGINE (/proc/net/dev)
// -------------------------------------------------------------
let lastNetSample = null;
let cachedNetInterface = null;

function formatBytesPerSec(bytes) {
    if (bytes < 1024) return `${bytes} B/s`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB/s`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB/s`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB/s`;
}

function formatTotalBytes(bytes) {
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function getNetworkMetrics() {
    try {
        if (process.platform !== 'linux' || !fs.existsSync('/proc/net/dev')) {
            return null;
        }

        const content = fs.readFileSync('/proc/net/dev', 'utf8');
        const lines = content.trim().split('\n').slice(2);
        const ifaces = [];

        for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length < 10) continue;
            const iface = parts[0].replace(':', '');
            if (iface === 'lo') continue;

            const rxBytes = parseInt(parts[1], 10);
            const rxPackets = parseInt(parts[2], 10);
            const txBytes = parseInt(parts[9], 10);
            const txPackets = parseInt(parts[10], 10);

            if (!isNaN(rxBytes) && !isNaN(txBytes)) {
                ifaces.push({ iface, rxBytes, txBytes, rxPackets, txPackets });
            }
        }

        if (ifaces.length === 0) return null;

        // Auto-select primary physical interface
        if (!cachedNetInterface) {
            const priorityList = ['eno1', 'eth0', 'enp', 'wlo1', 'wlan0'];
            for (const p of priorityList) {
                const match = ifaces.find(i => i.iface.startsWith(p));
                if (match) {
                    cachedNetInterface = match.iface;
                    break;
                }
            }
            if (!cachedNetInterface) {
                const nonVirtual = ifaces.filter(i => !i.iface.startsWith('br-') && !i.iface.startsWith('veth') && !i.iface.startsWith('docker'));
                cachedNetInterface = (nonVirtual.length > 0 ? nonVirtual : ifaces)[0].iface;
            }
        }

        const target = ifaces.find(i => i.iface === cachedNetInterface) || ifaces[0];
        const now = Date.now();

        if (!lastNetSample || lastNetSample.iface !== target.iface) {
            lastNetSample = {
                iface: target.iface,
                rxBytes: target.rxBytes,
                txBytes: target.txBytes,
                time: now
            };
            return {
                interface: target.iface,
                rxSec: 0,
                txSec: 0,
                rxFormatted: '0 B/s',
                txFormatted: '0 B/s',
                totalRxFormatted: formatTotalBytes(target.rxBytes),
                totalTxFormatted: formatTotalBytes(target.txBytes),
                rxPackets: target.rxPackets,
                txPackets: target.txPackets
            };
        }

        const elapsedSec = Math.max(0.1, (now - lastNetSample.time) / 1000);
        const deltaRx = Math.max(0, target.rxBytes - lastNetSample.rxBytes);
        const deltaTx = Math.max(0, target.txBytes - lastNetSample.txBytes);

        const rxSec = Math.round(deltaRx / elapsedSec);
        const txSec = Math.round(deltaTx / elapsedSec);

        lastNetSample = {
            iface: target.iface,
            rxBytes: target.rxBytes,
            txBytes: target.txBytes,
            time: now
        };

        return {
            interface: target.iface,
            rxSec: rxSec,
            txSec: txSec,
            rxFormatted: formatBytesPerSec(rxSec),
            txFormatted: formatBytesPerSec(txSec),
            totalRxFormatted: formatTotalBytes(target.rxBytes),
            totalTxFormatted: formatTotalBytes(target.txBytes),
            rxPackets: target.rxPackets,
            txPackets: target.txPackets
        };
    } catch (e) {
        return null;
    }
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
// 3. PM2 CONFIG MANAGER (PRESERVE USER CHOICES)
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
    } catch (err) {}

    if (!config.processes) config.processes = {};

    let hasChanges = false;
    for (const name of discoveredProcessNames) {
        if (name && config.processes[name] === undefined) {
            const isSelf = name.toLowerCase() === 'server-stats';
            config.processes[name] = {
                visible: !isSelf,
                addedAt: new Date().toISOString()
            };
            if (isSelf) {
                config.processes[name].note = "Host server process (hidden by default)";
            }
            hasChanges = true;
        }
    }

    if (hasChanges) {
        try {
            const tempFile = `${CONFIG_FILE}.tmp`;
            fs.writeFileSync(tempFile, JSON.stringify(config, null, 2), 'utf8');
            fs.renameSync(tempFile, CONFIG_FILE);
        } catch (writeErr) {}
    }

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
// 4. SANITIZED PM2 HEALTH MONITOR
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
            isPm2Connected = false;
            pm2State.available = false;
            return;
        }

        try {
            const now = Date.now();
            const names = list.map(p => p.name).filter(Boolean);
            const visibilityMap = syncPm2Config(names);

            const sanitizedProcesses = [];
            let total = 0, online = 0, stopped = 0, errored = 0;

            for (const p of list) {
                const name = p.name || 'unnamed';
                const isVisible = visibilityMap[name] !== false;

                if (!isVisible) continue;

                total++;
                const status = (p.pm2_env && p.pm2_env.status) ? p.pm2_env.status.toLowerCase() : 'unknown';
                if (status === 'online') online++;
                else if (status === 'stopped') stopped++;
                else if (status === 'errored') errored++;

                const restarts = (p.pm2_env && p.pm2_env.restart_time) || 0;
                const memoryBytes = (p.monit && p.monit.memory) || 0;
                const cpuPercent = (p.monit && typeof p.monit.cpu === 'number') ? p.monit.cpu : 0;
                const uptimeMs = (p.pm2_env && p.pm2_env.pm_uptime) ? (now - p.pm2_env.pm_uptime) : 0;

                // CRITICAL SECURITY HARDENING:
                // Omit internal OS PIDs, internal script paths, and exact node versions
                sanitizedProcesses.push({
                    id: p.pm_id !== undefined ? p.pm_id : null,
                    name: name,
                    status: status,
                    uptime: formatDuration(uptimeMs),
                    restarts: restarts,
                    restartAlert: restarts > 10,
                    memoryMB: parseFloat((memoryBytes / (1024 * 1024)).toFixed(1)),
                    cpu: parseFloat(cpuPercent.toFixed(1)),
                    mode: (p.pm2_env && p.pm2_env.exec_mode) || 'fork'
                });
            }

            sanitizedProcesses.sort((a, b) => {
                if (a.status === 'online' && b.status !== 'online') return -1;
                if (a.status !== 'online' && b.status === 'online') return 1;
                return a.name.localeCompare(b.name);
            });

            pm2State = {
                available: true,
                summary: { total, online, stopped, errored },
                processes: sanitizedProcesses
            };
        } catch (procErr) {
            console.error('[PM2] Processing error:', procErr.message);
        }
    });
}

if (pm2) {
    connectAndPollPm2();
    setInterval(connectAndPollPm2, 2500);
}

// -------------------------------------------------------------
// 5. HIGH-EFFICIENCY SINGLE-TICK BROADCAST ENGINE (O(1))
// -------------------------------------------------------------
let startMeasure = getCpuLoad();

// Centralized 1-second broadcast loop (never spikes CPU regardless of client count)
setInterval(() => {
    if (!wss.clients || wss.clients.size === 0) return;

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

    // 3. Compose Sanitized Payload (Masked Kernel, No PIDs)
    const tempObj = getCpuTemp();
    const net = getNetworkMetrics();
    const thermalList = getAllThermalSensors();

    const payload = {
        cpu: cpuPercentage,
        cpuModel: CPU_MODEL,
        cores: CPU_CORES,
        ram: parseFloat(mem.percent.toFixed(1)),
        time: new Date().toISOString(),
        temp: tempObj.temp,
        tempType: tempObj.type,
        loadAvg: os.loadavg().map(load => load.toFixed(2)),
        uptime: formatUptime(os.uptime()),

        // SECURITY MASKING: Generalized OS without exposing exact kernel CVE target
        osDetails: os.type() === 'Linux' ? 'Linux' : `${os.type()}`,
        architecture: os.arch(),
        hostname: 'PiCloud',

        ramDetails: {
            totalMB: mem.totalMB,
            usedMB: mem.usedMB,
            availableMB: mem.availableMB,
            freeMB: mem.freeMB,
            buffersMB: mem.buffersMB,
            cachedMB: mem.cachedMB
        },
        disk: disk,
        network: net,
        thermalDetails: thermalList,
        pm2: pm2State
    };

    const message = JSON.stringify(payload);

    // Broadcast to all active clients in one go
    for (const client of wss.clients) {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message);
        }
    }
}, 1000);

// Heartbeat interval to detect dead sockets & prevent file-descriptor leaks
const heartbeatInterval = setInterval(() => {
    for (const ws of wss.clients) {
        if (ws.isAlive === false) {
            ws.terminate();
            continue;
        }
        ws.isAlive = false;
        ws.ping();
    }
}, 30000);

wss.on('close', () => {
    clearInterval(heartbeatInterval);
});

// Client connection listener
wss.on('connection', (ws, req) => {
    ws.isAlive = true;
    ws.clientIp = getClientIp(req);

    ws.on('pong', () => {
        ws.isAlive = true;
    });

    ws.on('error', (err) => {
        console.warn(`[Client] Socket error from ${ws.clientIp}:`, err.message);
    });
});
