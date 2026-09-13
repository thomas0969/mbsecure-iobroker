/***********************************************************************
 * MB-Secure Auto Mirror
 * Version: 2.1.2 FINAL
 * READ/WRITE gegenüber der MB-Secure Service-Schnittstelle
 *
 * Experimentell bestätigte Schreibsemantik:
 * - PARTITION_CLEAR      = Bereich löschen / Supervisor Clear
 * - PARTITION_UNSET      = unscharf
 * - PARTITION_PARTSET    = intern scharf
 * - PARTITION_FULLSET    = extern scharf
 * - GROUP_OMIT_PART      = Meldergruppe intern sperren
 * - GROUP_UNOMIT_PART    = interne Sperre aufheben
 * - GROUP_OMIT_ALWAYS    = Meldergruppe extern sperren
 * - GROUP_UNOMIT_ALWAYS  = externe Sperre aufheben
 * - GROUP_BYPASS_ON      = einmalig übergehen
 * - GROUP_BYPASS_OFF     = Übergehen manuell aufheben
 * - OUTPUT_ON/OFF        = normaler Ausgang EIN/AUS
 *
 * Experimentell bestätigt:
 * - Einbruchklassifikation: atIntruder
 * - Sabotageklassifikation: atTamper
 * - Bypass ist einmalig und wird nach Unscharf automatisch gelöscht
 * - Result=OK allein genügt NICHT: jeder Schreibbefehl wird rückgelesen
 * - Login-Ablehnung erzeugt 5 Minuten absolute lokale Login-Sperre
 *
 * Bewusst NICHT freigegeben:
 * - Revision/Test/Störung
 * - Activate/Deactivate
 * - DetectorGroup OutputOn/Off
 * - Makro-/Benutzer-Schreibbefehle (mangels realem Testobjekt)
 *
 * Alarmklassen:
 * - rohe at... Felder bleiben vollständig gespiegelt
 * - atIntruder / atTamper praktisch verifiziert
 * - atFire / atPanic / atTechnical / atCarbonMonoxide /
 *   atFireSupervisory / atAlways / atNotSpecified werden aus der API
 *   gespiegelt, aber nicht hardwareseitig einzeln verifiziert
 * - Internalarm/Voralarm wird NICHT geraten; kein erfundener Mapping-DP
 ***********************************************************************/

const CFG = {
    host: '192.168.1.100',
    port: 444,
    base: '0_userdata.0.MBSecure',
    username: 'iobroker',
    password: 'HIER_DEIN_PASSWORT_EINTRAGEN',
    requestTimeoutMs: 12000,
    keepaliveMs: 20000,
    configPollMs: 20000,
    fullSyncMs: 15 * 60 * 1000,
    sseReconnectMs: 5000,
    eventRefreshDelayMs: 500,
    requestDelayMs: 60,
    loginRejectBlockMs: 5 * 60 * 1000,
    writeIdleWaitMs: 30000,
    writeVerifyDelayMs: 750,
    writeVerifyTries: 16,
    debug: false
};

const https = require('https');
const crypto = require('crypto');

let sid = null;
let generatorUID = null;
let paused = false;
let stopping = false;
let loginPromise = null;
let loginBlockedUntil = 0;
let loginBlockTimer = null;
let keepaliveTimer = null;
let configPollTimer = null;
let fullSyncTimer = null;
let sseRequest = null;
let sseReconnectTimer = null;
let eventRefreshTimer = null;
let fullSyncRunning = false;
let refreshRunning = false;
let refreshPending = false;
let lastChangeCounter = null;
let detectorGroups = [];
let partitionsCache = [];
let outputsCache = [];
let macrosCache = [];
let usersCache = [];
let powerCache = [];
let writeRunning = false;

const INVENTORY = {
    partitions: new Set(),
    groups: new Set(),
    members: new Set(),
    outputs: new Set(),
    normalOutputs: new Set(),
    macros: new Set(),
    users: new Set()
};

const UID = {
    SPAN: 629144,
    OUTPUT_NORMAL_START: 24117249,
    OUTPUT_SOUNDER_START: 30408705,
    OUTPUT_FLASHER_START: 19922945,
    SOUNDER_MAX: 31457280,
    FLASHER_MAX: 20971520,
    MACRO_START: 83886081,
    USER_START: 68157441
};

function dbg(message) { if (CFG.debug) log('[MB-Secure] ' + message, 'info'); }
function info(message) { log('[MB-Secure] ' + message, 'info'); }
function warn(message) { log('[MB-Secure] ' + message, 'warn'); }
function errorLog(message) { log('[MB-Secure] ' + message, 'error'); }
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
function nowIso() { return new Date().toISOString(); }
function md5(value) { return crypto.createHash('md5').update(String(value), 'utf8').digest('hex'); }
function safeJson(value) { try { return JSON.stringify(value); } catch (e) { return '{}'; } }
function valueOrEmpty(value) { return value === undefined || value === null ? '' : value; }

function encodeQueryValue(value) {
    return encodeURIComponent(String(value)).replace(/%2C/gi, ',');
}

function buildQuery(params) {
    const parts = [];
    Object.keys(params).forEach(key => {
        const value = params[key];
        if (value === undefined || value === null) return;
        parts.push(encodeURIComponent(key) + '=' + encodeQueryValue(value));
    });
    return parts.join('&');
}

function normalizeList(data) {
    if (!data || typeof data !== 'object' || !Array.isArray(data.List)) return [];
    return data.List.filter(item => item && typeof item === 'object');
}

function nextRange(start, end, previous, blockSize, previousCount) {
    const maxBlock = 10000;
    let size = blockSize || 20;

    if (previousCount !== undefined && !previousCount && previous) {
        const previousSize = previous[1] - previous[0] + 1;
        if (previousSize === maxBlock) return null;
        size = maxBlock;
    }

    if (previous && previous[1] >= end) return null;

    const range = [start, end];
    if (previous) range[0] = previous[1] + 1;
    range[1] = range[0] + size - 1;
    if (range[1] > end) range[1] = end;
    if ((range[1] - range[0]) > maxBlock) range[1] = range[0] + maxBlock;
    return range;
}

function uidString(value) {
    if (value === undefined || value === null) return '';
    const s = String(value).trim();
    return /^\d+$/.test(s) ? s : '';
}

function flagValue(value) {
    if (typeof value === 'boolean') return value;
    if (typeof value === 'number') return value !== 0;
    const s = String(value === undefined || value === null ? '' : value).trim().toLowerCase();
    return s === '1' || s === 'true' || s === 'on' || s === 'yes';
}

function findByUID(list, uid) {
    const wanted = uidString(uid);
    if (!wanted || !Array.isArray(list)) return null;
    return list.find(item => item && uidString(item.UID) === wanted) || null;
}

function activeAlarmTypeNames(partition) {
    if (!partition || typeof partition !== 'object') return [];
    return Object.keys(partition)
        .filter(key => key.startsWith('at') && flagValue(partition[key]))
        .sort();
}

function clearInventory() {
    Object.keys(INVENTORY).forEach(key => INVENTORY[key].clear());
}

function ensureState(id, initialValue, common) {
    return new Promise(resolve => {
        if (existsState(id)) return resolve();
        createState(id, initialValue, false, common, {}, () => resolve());
    });
}

function convertValueForState(id, value) {
    let obj = null;
    try { obj = getObject(id); } catch (e) { obj = null; }
    if (!obj || !obj.common || !obj.common.type) return value;

    const type = obj.common.type;
    if (type === 'string') {
        if (value === undefined || value === null) return '';
        return typeof value === 'object' ? safeJson(value) : String(value);
    }
    if (type === 'number') {
        if (value === undefined || value === null || value === '') return 0;
        if (typeof value === 'boolean') return value ? 1 : 0;
        const n = Number(value);
        if (Number.isFinite(n)) return n;
        warn('Kann Wert für Number-State nicht konvertieren: ' + id + ' = ' + String(value));
        return 0;
    }
    if (type === 'boolean') {
        if (typeof value === 'boolean') return value;
        if (typeof value === 'number') return value !== 0;
        if (typeof value === 'string') {
            const s = value.trim().toLowerCase();
            if (['true', '1', 'on', 'yes'].includes(s)) return true;
            if (['false', '0', 'off', 'no', ''].includes(s)) return false;
        }
        return !!value;
    }
    return value;
}

function writeState(id, value) {
    return new Promise(resolve => {
        if (!existsState(id)) {
            return resolve(false);
        }

        let finalValue = value;

        try {
            finalValue = convertValueForState(id, value);
        } catch (e) {
            warn('Typkonvertierung fehlgeschlagen für ' + id + ': ' + e.message);
        }

        let current = null;
        try {
            current = getState(id);
        } catch (e) {
            current = null;
        }

        // v2.1.1: unveränderte, bereits bestätigte Mirror-Werte nicht erneut schreiben.
        if (current && current.ack === true && Object.is(current.val, finalValue)) {
            return resolve(false);
        }

        setState(id, finalValue, true, () => resolve(true));
    });
}

async function ensureString(id, name, initialValue) {
    await ensureState(id, initialValue === undefined ? '' : String(initialValue), {
        name, type: 'string', role: 'text', read: true, write: false
    });
}

async function ensureNumber(id, name, initialValue) {
    let v = Number(initialValue);
    if (!Number.isFinite(v)) v = 0;
    await ensureState(id, v, {
        name,
        type: 'number',
        role: 'value',
        read: true,
        write: false
    });
}

async function ensureBoolean(id, name, initialValue) {
    await ensureState(id, !!initialValue, {
        name,
        type: 'boolean',
        role: 'indicator',
        read: true,
        write: false
    });
}

async function createSystemStates() {
    await ensureString(CFG.base + '.System.ScriptVersion', 'Script Version', '2.1.2');
    await ensureBoolean(CFG.base + '.System.Connected', 'MB-Secure verbunden', false);
    await ensureBoolean(CFG.base + '.System.SessionActive', 'Service Session aktiv', false);
    await ensureBoolean(CFG.base + '.System.LoginInProgress', 'Login läuft', false);
    await ensureString(CFG.base + '.System.LastLogin', 'Letzter Login', '');
    await ensureString(CFG.base + '.System.LastFullSync', 'Letzter FullSync', '');
    await ensureString(CFG.base + '.System.LastStateRefresh', 'Letzter Status Refresh', '');
    await ensureString(CFG.base + '.System.LastRefreshReason', 'Grund letzter Status Refresh', '');
    await ensureString(CFG.base + '.System.LastSSEEvent', 'Letztes SSE Ereignis', '');
    await ensureString(CFG.base + '.System.LastError', 'Letzter Fehler', '');
    await ensureNumber(CFG.base + '.System.ChangeCounter', 'MB-Secure ChangeCounter', 0);
    await ensureNumber(CFG.base + '.System.PartitionCount', 'Anzahl Bereiche', 0);
    await ensureNumber(CFG.base + '.System.DetectorGroupCount', 'Anzahl Meldergruppen', 0);
    await ensureNumber(CFG.base + '.System.DetectorMemberCount', 'Anzahl Member-Zuordnungen', 0);
    await ensureNumber(CFG.base + '.System.LiveGroupCount', 'Meldergruppen mit Live-State', 0);
    await ensureNumber(CFG.base + '.System.InputCount', 'Anzahl eindeutige Inputs', 0);
    await ensureNumber(CFG.base + '.System.PIRCount', 'Anzahl eindeutige PIRs', 0);
    await ensureNumber(CFG.base + '.System.SmokeCount', 'Anzahl eindeutige Rauchmelder', 0);
    await ensureBoolean(CFG.base + '.System.LoginBlocked', 'Login Sicherheitsblockade aktiv', false);
    await ensureString(CFG.base + '.System.LoginBlockedUntil', 'Login blockiert bis', '');
    await ensureString(CFG.base + '.System.LastLoginReject', 'Letzte Login-Ablehnung', '');

    await ensureState(CFG.base + '.Control.Pause', false, {
        name: 'MB-Secure Mirror pausieren',
        type: 'boolean',
        role: 'switch',
        read: true,
        write: true
    });

    await ensureState(CFG.base + '.Control.FullSync', false, {
        name: 'MB-Secure FullSync auslösen',
        type: 'boolean',
        role: 'button',
        read: true,
        write: true
    });

    await ensureNumber(CFG.base + '.System.OutputCount', 'Anzahl Ausgänge', 0);
    await ensureNumber(CFG.base + '.System.MacroCount', 'Anzahl Makros', 0);
    await ensureNumber(CFG.base + '.System.UserCount', 'Anzahl Benutzer', 0);
    await ensureNumber(CFG.base + '.System.PowerDeviceCount', 'Anzahl Netzteile', 0);
    await ensureNumber(CFG.base + '.System.NormalOutputCount', 'Anzahl normale Ausgänge', 0);

    await ensureString(
        CFG.base + '.System.AlarmMappingInfo',
        'Alarmklassen Hinweis',
        'atIntruder=Einbruch und atTamper=Sabotage praktisch verifiziert; weitere at... Klassen aus API; Internalarm/Voralarm nicht geraten.'
    );

    await ensureState(CFG.base + '.Control.Write.Enabled', false, {
        name: 'Schreibzugriff freigeben',
        type: 'boolean',
        role: 'switch',
        read: true,
        write: true
    });

    await ensureState(CFG.base + '.Control.Write.Command', '', {
        name: 'Schreibbefehl',
        type: 'string',
        role: 'text',
        read: true,
        write: true
    });

    await ensureState(CFG.base + '.Control.Write.TargetUID', '', {
        name: 'Ziel UID',
        type: 'string',
        role: 'text',
        read: true,
        write: true
    });

    await ensureState(CFG.base + '.Control.Write.Execute', false, {
        name: 'Schreibbefehl ausführen',
        type: 'boolean',
        role: 'button',
        read: true,
        write: true
    });

    await ensureBoolean(CFG.base + '.Control.Write.Busy', 'Schreibbefehl läuft', false);
    await ensureString(CFG.base + '.Control.Write.LastCommand', 'Letzter Schreibbefehl', '');
    await ensureString(CFG.base + '.Control.Write.LastResult', 'Letztes Schreibergebnis', '');
    await ensureString(CFG.base + '.Control.Write.LastError', 'Letzter Schreibfehler', '');
    await ensureString(CFG.base + '.Control.Write.LastTime', 'Zeit letzter Schreibbefehl', '');
    await ensureBoolean(
        CFG.base + '.Control.Write.LastVerified',
        'Letzter Schreibbefehl per Readback bestätigt',
        false
    );
    await ensureString(
        CFG.base + '.Control.Write.LastVerification',
        'Readback-Verifikation',
        ''
    );

    await ensureString(
        CFG.base + '.Control.Write.CommandHelp',
        'Erlaubte Schreibbefehle',
        'PARTITION_CLEAR, PARTITION_UNSET, PARTITION_PARTSET, PARTITION_FULLSET, OUTPUT_OFF, OUTPUT_ON, GROUP_BYPASS_ON, GROUP_BYPASS_OFF, GROUP_OMIT_PART, GROUP_UNOMIT_PART, GROUP_OMIT_ALWAYS, GROUP_UNOMIT_ALWAYS'
    );

    await ensureString(CFG.base + '.Info.PanelVersion', 'MB-Secure Version', '');
    await ensureString(CFG.base + '.Info.ClientType', 'Client Type', '');
    await ensureString(CFG.base + '.Info.GeneratorUID', 'Generator UID', '');

    await writeState(CFG.base + '.System.ScriptVersion', '2.1.2');
    await writeState(CFG.base + '.System.LoginInProgress', false);
}

function isLoginBlocked() {
    return loginBlockedUntil > 0 && Date.now() < loginBlockedUntil;
}

function clearLoginBlockTimer() {
    if (loginBlockTimer) {
        clearTimeout(loginBlockTimer);
        loginBlockTimer = null;
    }
}

function createLoginBlockedError() {
    const e = new Error('Login-Sicherheitswartezeit aktiv.');
    e.code = 'MB_LOGIN_BLOCKED';
    return e;
}

function createLoginRejectedError(reason) {
    const e = new Error(reason);
    e.code = 'MB_LOGIN_REJECTED';
    return e;
}

function isLoginBlockedError(e) {
    return !!(e && e.code === 'MB_LOGIN_BLOCKED');
}

function isLoginRejectedError(e) {
    return !!(e && e.code === 'MB_LOGIN_REJECTED');
}

async function restoreLoginBlock() {
    const st = getState(CFG.base + '.System.LoginBlockedUntil');
    let until = 0;

    if (st && st.val) {
        const parsed = Date.parse(String(st.val));
        if (Number.isFinite(parsed) && parsed > Date.now()) {
            until = parsed;
        }
    }

    if (until > 0) {
        loginBlockedUntil = until;
        await writeState(CFG.base + '.System.LoginBlocked', true);
        info(
            'Vorhandene Login-Sicherheitswartezeit wiederhergestellt. Bis ' +
            new Date(until).toISOString() +
            ' erfolgt kein Loginversuch.'
        );
        return true;
    }

    loginBlockedUntil = 0;
    await writeState(CFG.base + '.System.LoginBlocked', false);
    await writeState(CFG.base + '.System.LoginBlockedUntil', '');
    return false;
}

async function activateLoginBlock(reason) {
    loginBlockedUntil = Date.now() + CFG.loginRejectBlockMs;
    sid = null;
    generatorUID = null;

    clearLoginBlockTimer();

    if (sseReconnectTimer) {
        clearTimeout(sseReconnectTimer);
        sseReconnectTimer = null;
    }

    stopSSEConnectionOnly();

    await writeState(CFG.base + '.System.Connected', false);
    await writeState(CFG.base + '.System.SessionActive', false);
    await writeState(CFG.base + '.System.LoginBlocked', true);
    await writeState(CFG.base + '.Control.Write.Enabled', false);
    await writeState(
        CFG.base + '.System.LoginBlockedUntil',
        new Date(loginBlockedUntil).toISOString()
    );
    await writeState(
        CFG.base + '.System.LastLoginReject',
        nowIso() + ' ' + reason
    );

    warn(
        'Login von Zentrale abgewiesen. Für 5 Minuten wird KEIN weiterer Loginversuch gesendet.'
    );

    scheduleLoginAfterBlock();
}

function scheduleLoginAfterBlock() {
    clearLoginBlockTimer();

    if (stopping || paused || !loginBlockedUntil) {
        return;
    }

    const delay = Math.max(
        1000,
        loginBlockedUntil - Date.now() + 1000
    );

    loginBlockTimer = setTimeout(
        runLoginAfterBlock,
        delay
    );
}

async function runLoginAfterBlock() {
    loginBlockTimer = null;

    if (stopping || paused) {
        return;
    }

    if (isLoginBlocked()) {
        scheduleLoginAfterBlock();
        return;
    }

    loginBlockedUntil = 0;

    await writeState(CFG.base + '.System.LoginBlocked', false);
    await writeState(CFG.base + '.System.LoginBlockedUntil', '');

    info(
        'Login-Sicherheitswartezeit abgelaufen. Es erfolgt genau ein neuer Loginversuch.'
    );

    try {
        await login();
        await fullSync('nach Login-Sicherheitswartezeit');
        startTimers();
    } catch (e) {
        if (isLoginBlockedError(e) || isLoginRejectedError(e)) {
            return;
        }

        await handleError(
            'Login nach Sicherheitswartezeit',
            e
        );

        scheduleSSEReconnect();
    }
}

function httpsRequest(path, headers) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: CFG.host,
            port: CFG.port,
            path,
            method: 'GET',
            rejectUnauthorized: false,
            headers: Object.assign(
                {
                    Accept: 'application/json',
                    Connection: 'close'
                },
                headers || {}
            )
        };

        const req = https.request(
            options,
            res => {
                let body = '';

                res.setEncoding('utf8');

                res.on(
                    'data',
                    chunk => body += chunk
                );

                res.on(
                    'end',
                    () => {
                        let data;

                        try {
                            data = JSON.parse(body);
                        } catch (e) {
                            data = {
                                _RawText: body
                            };
                        }

                        resolve({
                            statusCode: res.statusCode,
                            headers: res.headers,
                            data
                        });
                    }
                );
            }
        );

        req.setTimeout(
            CFG.requestTimeoutMs,
            () => req.destroy(
                new Error('Request timeout')
            )
        );

        req.on(
            'error',
            reject
        );

        req.end();
    });
}

async function login() {
    if (isLoginBlocked()) {
        throw createLoginBlockedError();
    }

    if (sid) {
        return;
    }

    if (loginPromise) {
        return await loginPromise;
    }

    loginPromise = performLogin();

    try {
        return await loginPromise;
    } finally {
        loginPromise = null;
    }
}

async function performLogin() {
    if (isLoginBlocked()) {
        throw createLoginBlockedError();
    }

    if (sid) {
        return;
    }

    if (
        !CFG.username ||
        !CFG.password ||
        CFG.password === 'HIER_DEIN_PASSWORT_EINTRAGEN'
    ) {
        throw new Error(
            'Benutzername/Passwort fehlen in CFG.'
        );
    }

    await writeState(
        CFG.base + '.System.LoginInProgress',
        true
    );

    try {
        const passwordHash = md5(CFG.password);

        const auth = Buffer.from(
            CFG.username + ':' + passwordHash,
            'utf8'
        ).toString('base64');

        const query = buildQuery({
            cmd: 'command',
            type: 'ccCMDAPPISOMGetInfo',
            SubCmd: 'cstConfigInfo',
            option: 0
        });

        const response = await httpsRequest(
            '/panel?' + query,
            {
                Authorization: 'Basic ' + auth
            }
        );

        if (
            [401, 403, 423, 429].includes(
                response.statusCode
            )
        ) {
            const reason =
                'Login HTTP ' +
                response.statusCode;

            await activateLoginBlock(reason);

            throw createLoginRejectedError(
                reason
            );
        }

        if (response.statusCode !== 200) {
            throw new Error(
                'Login HTTP ' +
                response.statusCode
            );
        }

        if (
            !response.data ||
            response.data.Result !== 'OK'
        ) {
            const reason =
                'Login Result=' +
                (
                    response.data
                        ? String(response.data.Result)
                        : 'undefined'
                );

            await activateLoginBlock(reason);

            throw createLoginRejectedError(
                reason
            );
        }

        const newSid =
            response.headers['x-my-sid'];

        if (!newSid) {
            throw new Error(
                'Login erfolgreich, aber X-My-SID fehlt.'
            );
        }

        const newGeneratorUID =
            String(
                response.data.GeneratorUID || ''
            );

        if (!newGeneratorUID) {
            throw new Error(
                'GeneratorUID fehlt.'
            );
        }

        sid = newSid;
        generatorUID = newGeneratorUID;
        loginBlockedUntil = 0;

        clearLoginBlockTimer();

        await writeState(
            CFG.base + '.System.LoginBlocked',
            false
        );

        await writeState(
            CFG.base + '.System.LoginBlockedUntil',
            ''
        );

        await writeState(
            CFG.base + '.System.Connected',
            true
        );

        await writeState(
            CFG.base + '.System.SessionActive',
            true
        );

        await writeState(
            CFG.base + '.System.LastLogin',
            nowIso()
        );

        await writeState(
            CFG.base + '.System.LastError',
            ''
        );

        await writeState(
            CFG.base + '.Info.PanelVersion',
            valueOrEmpty(
                response.data.Version
            )
        );

        await writeState(
            CFG.base + '.Info.ClientType',
            valueOrEmpty(
                response.data.ClientType
            )
        );

        await writeState(
            CFG.base + '.Info.GeneratorUID',
            generatorUID
        );

        if (
            response.data.ChangeCounter !== undefined
        ) {
            const c = Number(
                response.data.ChangeCounter
            );

            if (Number.isFinite(c)) {
                lastChangeCounter = c;

                await writeState(
                    CFG.base + '.System.ChangeCounter',
                    c
                );
            }
        }

        info(
            'Login OK: ' +
            valueOrEmpty(response.data.ClientType) +
            ', Version ' +
            valueOrEmpty(response.data.Version)
        );

    } finally {
        await writeState(
            CFG.base + '.System.LoginInProgress',
            false
        );
    }
}

async function logout() {
    stopSSEConnectionOnly();

    if (!sid || !generatorUID) {
        sid = null;
        generatorUID = null;

        await writeState(
            CFG.base + '.System.SessionActive',
            false
        );

        await writeState(
            CFG.base + '.System.Connected',
            false
        );

        return;
    }

    const oldSid = sid;
    const oldGeneratorUID = generatorUID;

    sid = null;
    generatorUID = null;

    try {
        const query = buildQuery({
            cmd: 'logout',
            userid: oldGeneratorUID
        });

        await httpsRequest(
            '/panel?' + query,
            {
                'X-My-SID': oldSid
            }
        );

    } catch (e) {
        dbg(
            'Logout Fehler: ' +
            e.message
        );
    }

    await writeState(
        CFG.base + '.System.SessionActive',
        false
    );

    await writeState(
        CFG.base + '.System.Connected',
        false
    );
}

async function panelCommand(
    type,
    params,
    retryAfter401
) {
    if (retryAfter401 === undefined) {
        retryAfter401 = true;
    }

    if (!sid) {
        if (isLoginBlocked()) {
            throw createLoginBlockedError();
        }

        await login();
    }

    const q = {
        cmd: 'command',
        userid: generatorUID,
        type
    };

    Object.keys(
        params || {}
    ).forEach(
        key => q[key] = params[key]
    );

    const response = await httpsRequest(
        '/panel?' + buildQuery(q),
        {
            'X-My-SID': sid
        }
    );

    if (response.statusCode === 401) {
        if (!retryAfter401) {
            throw new Error(
                type +
                ': HTTP 401 nach Re-Login'
            );
        }

        warn(
            'Session ungültig. Ein kontrollierter Re-Login wird versucht.'
        );

        sid = null;
        generatorUID = null;

        await writeState(
            CFG.base + '.System.SessionActive',
            false
        );

        await writeState(
            CFG.base + '.System.Connected',
            false
        );

        await login();

        return panelCommand(
            type,
            params,
            false
        );
    }

    if (response.statusCode !== 200) {
        throw new Error(
            type +
            ': HTTP ' +
            response.statusCode
        );
    }

    return response.data;
}

async function mirrorObject(base, obj) {
    if (!obj || typeof obj !== 'object') {
        return false;
    }

    let changed = false;

    for (const key of Object.keys(obj)) {
        const value = obj[key];

        if (
            value === undefined ||
            value === null
        ) {
            continue;
        }

        const id =
            base +
            '.' +
            key;

        if (typeof value === 'boolean') {
            await ensureBoolean(
                id,
                key,
                value
            );

        } else if (typeof value === 'number') {
            await ensureNumber(
                id,
                key,
                value
            );

        } else {
            await ensureString(
                id,
                key,
                typeof value === 'string'
                    ? value
                    : ''
            );
        }

        if (await writeState(
            id,
            typeof value === 'object'
                ? safeJson(value)
                : value
        )) {
            changed = true;
        }
    }

    await ensureString(
        base + '._Raw',
        'Raw JSON',
        ''
    );

    if (await writeState(
        base + '._Raw',
        safeJson(obj)
    )) {
        changed = true;
    }

    return changed;
}

async function mirrorPartitionAlarmClasses(item) {
    if (
        !item ||
        item.UID === undefined
    ) {
        return;
    }

    const base =
        CFG.base +
        '.Partitions.' +
        String(item.UID) +
        '.AlarmClasses';

    const mapping = {
        AnyAlarm: [
            'Alarm',
            'Alarm gesamt'
        ],

        Intruder: [
            'atIntruder',
            'Einbruch (praktisch verifiziert)'
        ],

        Tamper: [
            'atTamper',
            'Sabotage (praktisch verifiziert)'
        ],

        Fire: [
            'atFire',
            'Brand (API, nicht praktisch verifiziert)'
        ],

        FireSupervisory: [
            'atFireSupervisory',
            'Brand Supervisory (API, nicht praktisch verifiziert)'
        ],

        Panic: [
            'atPanic',
            'Überfall/Panik (API, laut/still hier nicht differenziert)'
        ],

        Technical: [
            'atTechnical',
            'Technischer Alarm (API, nicht praktisch verifiziert)'
        ],

        CarbonMonoxide: [
            'atCarbonMonoxide',
            'CO Alarm (API, nicht praktisch verifiziert)'
        ],

        Always: [
            'atAlways',
            'Alarmklasse Always (API)'
        ],

        NotSpecified: [
            'atNotSpecified',
            'Nicht spezifizierte Zusatzklassifikation (API)'
        ]
    };

    for (
        const [name, def]
        of Object.entries(mapping)
    ) {
        await ensureBoolean(
            base + '.' + name,
            def[1],
            false
        );

        await writeState(
            base + '.' + name,
            flagValue(
                item[def[0]]
            )
        );
    }

    await ensureString(
        base + '.ActiveTypes',
        'Aktive rohe at... Alarmtypen',
        ''
    );

    await writeState(
        base + '.ActiveTypes',
        activeAlarmTypeNames(item).join(',')
    );

    await ensureString(
        base + '.ArmingState',
        'Scharfschaltzustand bei letzter Abfrage',
        ''
    );

    await writeState(
        base + '.ArmingState',
        valueOrEmpty(item.SetState)
    );

    await ensureBoolean(
        base + '.VerifiedIntruderMapping',
        'atIntruder praktisch verifiziert',
        true
    );

    await ensureBoolean(
        base + '.VerifiedTamperMapping',
        'atTamper praktisch verifiziert',
        true
    );

    await writeState(
        base + '.VerifiedIntruderMapping',
        true
    );

    await writeState(
        base + '.VerifiedTamperMapping',
        true
    );
}

async function mirrorGroupSemantics(group) {
    if (
        !group ||
        group.UID === undefined
    ) {
        return;
    }

    const base =
        CFG.base +
        '.DetectorGroups.' +
        String(group.UID) +
        '.Semantics';

    const omitType =
        String(
            group.OmitType || ''
        );

    await ensureBoolean(
        base + '.InternalBlocked',
        'Intern gesperrt (otPartSet)',
        false
    );

    await ensureBoolean(
        base + '.ExternalBlocked',
        'Extern gesperrt (otAlways)',
        false
    );

    await ensureBoolean(
        base + '.Bypassed',
        'Einmalig übergangen',
        false
    );

    await ensureBoolean(
        base + '.Released',
        'Meldergruppe ausgelöst/freigegeben',
        false
    );

    await ensureBoolean(
        base + '.Alarm',
        'Meldergruppenalarm',
        false
    );

    await ensureBoolean(
        base + '.Fault',
        'Meldergruppenstörung',
        false
    );

    // MB-Secure kennt vier relevante Sperrzustände:
    // otNone          = keine Sperre
    // otPartSet       = nur intern gesperrt
    // otAlways        = nur extern gesperrt
    // otAlwaysPartSet = intern UND extern gesperrt
    //
    // Wichtig: intern/extern sind damit keine gegenseitig
    // ausschließenden Zustände.
    await writeState(
        base + '.InternalBlocked',
        omitType === 'otPartSet' ||
        omitType === 'otAlwaysPartSet'
    );

    await writeState(
        base + '.ExternalBlocked',
        omitType === 'otAlways' ||
        omitType === 'otAlwaysPartSet'
    );

    await writeState(
        base + '.Bypassed',
        flagValue(group.Bypass)
    );

    await writeState(
        base + '.Released',
        flagValue(group.Release)
    );

    await writeState(
        base + '.Alarm',
        flagValue(group.Alarm)
    );

    await writeState(
        base + '.Fault',
        flagValue(group.Fault)
    );
}

async function readPartitions() {
    const data = await panelCommand(
        'ccCMDAPPPartitionStates',
        {
            ExecutorUIDs: '1048577-1048586',
            Text: 1
        }
    );

    const list =
        normalizeList(data);

    for (const item of list) {
        await mirrorObject(
            CFG.base +
            '.Partitions.' +
            String(item.UID),
            item
        );

        await mirrorPartitionAlarmClasses(
            item
        );
    }

    partitionsCache = list;

    INVENTORY.partitions.clear();

    list.forEach(item => {
        const uid =
            uidString(item.UID);

        if (uid) {
            INVENTORY.partitions.add(uid);
        }
    });

    await writeState(
        CFG.base + '.System.PartitionCount',
        list.length
    );

    return list;
}

async function readDetectorGroups(partition) {
    const partitionUID =
        String(partition.UID);

    const data = await panelCommand(
        'ccCMDAPPDetectorGroupStates',
        {
            Partition: partitionUID,
            ExecutorUIDs: '',
            Text: 1
        }
    );

    const list =
        normalizeList(data);

    for (const group of list) {
        const groupUID =
            String(group.UID);

        const base =
            CFG.base +
            '.DetectorGroups.' +
            groupUID;

        await mirrorObject(
            base,
            group
        );

        await mirrorGroupSemantics(
            group
        );

        await ensureString(
            base + '.PartitionUID',
            'Partition UID',
            ''
        );

        await writeState(
            base + '.PartitionUID',
            partitionUID
        );

        INVENTORY.groups.add(
            groupUID
        );
    }

    return list;
}

async function readDetectorMembers(
    partition,
    group
) {
    const groupUID =
        String(group.UID);

    const data = await panelCommand(
        'ccCMDAPPDetectorGroupMember',
        {
            SubCmd: 'cstGetMember',
            ExecutorUIDs: groupUID,
            Text: 1
        }
    );

    const members =
        normalizeList(data);

    const memberUIDs = [];

    for (const member of members) {
        const memberUID =
            String(member.UID);

        memberUIDs.push(
            memberUID
        );

        INVENTORY.members.add(
            memberUID
        );

        const globalBase =
            CFG.base +
            '.DetectorMembers.' +
            memberUID;

        await mirrorObject(
            globalBase,
            member
        );

        const groupBase =
            CFG.base +
            '.DetectorGroups.' +
            groupUID +
            '.Members.' +
            memberUID;

        await mirrorObject(
            groupBase,
            member
        );

        await ensureString(
            groupBase + '.PartitionUID',
            'Partition UID',
            ''
        );

        await writeState(
            groupBase + '.PartitionUID',
            String(partition.UID)
        );
    }

    const base =
        CFG.base +
        '.DetectorGroups.' +
        groupUID;

    await ensureNumber(
        base + '.MemberCount',
        'Anzahl Mitglieder',
        0
    );

    await writeState(
        base + '.MemberCount',
        members.length
    );

    await ensureString(
        base + '.MemberUIDs',
        'Member UIDs',
        ''
    );

    await writeState(
        base + '.MemberUIDs',
        memberUIDs.join(',')
    );

    return members;
}


/***********************************************************************
 * WEITERE INVENTARE:
 * AUSGÄNGE / MAKROS / BENUTZER / NETZTEILE
 ***********************************************************************/

async function discoverRange(
    start,
    end,
    blockSize,
    fetchBlock
) {
    const result = [];

    let range = nextRange(
        start,
        end,
        null,
        blockSize,
        undefined
    );

    while (
        range &&
        !paused &&
        !stopping &&
        !isLoginBlocked()
    ) {
        const list =
            await fetchBlock(
                range[0] +
                '-' +
                range[1]
            );

        result.push(
            ...list
        );

        range = nextRange(
            start,
            end,
            range,
            blockSize,
            list.length
        );

        await sleep(
            CFG.requestDelayMs
        );
    }

    return result;
}

async function readOutputsInventory() {
    const starts = [
        UID.OUTPUT_NORMAL_START,
        UID.OUTPUT_SOUNDER_START,
        UID.OUTPUT_FLASHER_START
    ];

    const all = [];

    for (const start of starts) {
        const list = await discoverRange(
            start,
            start + UID.SPAN,
            30,
            async range =>
                normalizeList(
                    await panelCommand(
                        'ccCMDAPPMOutput',
                        {
                            SubCmd: 'cstGetDevice',
                            ExecutorUIDs: range,
                            PartitionMemberUID: 0,
                            Text: 1
                        }
                    )
                )
        );

        all.push(
            ...list
        );
    }

    const unique =
        new Map();

    all.forEach(item => {
        const uid =
            uidString(item.UID);

        if (uid) {
            unique.set(
                uid,
                item
            );
        }
    });

    outputsCache =
        Array.from(
            unique.values()
        );

    INVENTORY.outputs.clear();
    INVENTORY.normalOutputs.clear();

    for (const item of outputsCache) {
        const uid =
            uidString(item.UID);

        if (!uid) {
            continue;
        }

        INVENTORY.outputs.add(
            uid
        );

        const n =
            Number(uid);

        if (
            !(
                n >= UID.OUTPUT_SOUNDER_START &&
                n <= UID.SOUNDER_MAX
            ) &&
            !(
                n >= UID.OUTPUT_FLASHER_START &&
                n <= UID.FLASHER_MAX
            )
        ) {
            INVENTORY.normalOutputs.add(
                uid
            );
        }

        await mirrorObject(
            CFG.base +
            '.Outputs.' +
            uid,
            item
        );
    }

    await refreshOutputStates();

    await writeState(
        CFG.base + '.System.OutputCount',
        outputsCache.length
    );

    await writeState(
        CFG.base + '.System.NormalOutputCount',
        INVENTORY.normalOutputs.size
    );

    return outputsCache;
}

async function refreshOutputStates() {
    if (!outputsCache.length) {
        return;
    }

    const normal = [];
    const sounder = [];
    const flasher = [];

    outputsCache.forEach(item => {
        const uid =
            uidString(item.UID);

        if (!uid) {
            return;
        }

        const n =
            Number(uid);

        if (
            n >= UID.OUTPUT_SOUNDER_START &&
            n <= UID.SOUNDER_MAX
        ) {
            sounder.push(uid);

        } else if (
            n >= UID.OUTPUT_FLASHER_START &&
            n <= UID.FLASHER_MAX
        ) {
            flasher.push(uid);

        } else {
            normal.push(uid);
        }
    });

    const batches = [
        [
            'ccCMDAPPOutputStates',
            normal
        ],
        [
            'ccCMDAPPSounderStates',
            sounder
        ],
        [
            'ccCMDAPPFlasherStates',
            flasher
        ]
    ];

    for (
        const [type, uids]
        of batches
    ) {
        if (!uids.length) {
            continue;
        }

        const list = normalizeList(
            await panelCommand(
                type,
                {
                    ExecutorUIDs:
                        uids.join(',')
                }
            )
        );

        for (const item of list) {
            const uid =
                uidString(item.UID);

            if (uid) {
                await mirrorObject(
                    CFG.base +
                    '.Outputs.' +
                    uid,
                    item
                );
            }
        }
    }
}

async function readMacrosInventory() {
    macrosCache = await discoverRange(
        UID.MACRO_START,
        UID.MACRO_START + UID.SPAN,
        20,
        async range =>
            normalizeList(
                await panelCommand(
                    'ccCMDAPPMMacro',
                    {
                        SubCmd: 'cstGetDevice',
                        ExecutorUIDs: range,
                        Text: 1
                    }
                )
            )
    );

    INVENTORY.macros.clear();

    for (const item of macrosCache) {
        const uid =
            uidString(item.UID);

        if (!uid) {
            continue;
        }

        INVENTORY.macros.add(
            uid
        );

        await mirrorObject(
            CFG.base +
            '.Macros.' +
            uid,
            item
        );
    }

    await refreshMacroStates();

    await writeState(
        CFG.base + '.System.MacroCount',
        macrosCache.length
    );

    return macrosCache;
}

async function refreshMacroStates() {
    const uids =
        macrosCache
            .map(
                x => uidString(x.UID)
            )
            .filter(Boolean);

    if (!uids.length) {
        return;
    }

    const list = normalizeList(
        await panelCommand(
            'ccCMDAPPMacroStates',
            {
                ExecutorUIDs:
                    uids.join(',')
            }
        )
    );

    for (const item of list) {
        const uid =
            uidString(item.UID);

        if (uid) {
            await mirrorObject(
                CFG.base +
                '.Macros.' +
                uid,
                item
            );
        }
    }
}

async function readUsersInventory() {
    usersCache = await discoverRange(
        UID.USER_START,
        UID.USER_START + UID.SPAN,
        20,
        async range =>
            normalizeList(
                await panelCommand(
                    'ccCMDAPPUserStates',
                    {
                        ExecutorUIDs: range,
                        Text: 1
                    }
                )
            )
    );

    INVENTORY.users.clear();

    for (const item of usersCache) {
        const uid =
            uidString(item.UID);

        if (!uid) {
            continue;
        }

        INVENTORY.users.add(
            uid
        );

        await mirrorObject(
            CFG.base +
            '.Users.' +
            uid,
            item
        );
    }

    await writeState(
        CFG.base + '.System.UserCount',
        usersCache.length
    );

    return usersCache;
}

async function refreshUserStates() {
    const uids =
        usersCache
            .map(
                x => uidString(x.UID)
            )
            .filter(Boolean);

    if (!uids.length) {
        return;
    }

    const list = normalizeList(
        await panelCommand(
            'ccCMDAPPUserStates',
            {
                ExecutorUIDs:
                    uids.join(',')
            }
        )
    );

    for (const item of list) {
        const uid =
            uidString(item.UID);

        if (uid) {
            await mirrorObject(
                CFG.base +
                '.Users.' +
                uid,
                item
            );
        }
    }
}

async function readPowerInventory() {
    powerCache = normalizeList(
        await panelCommand(
            'ccCMDAPPPowerMonitoringDevice',
            {
                SubCmd: 'cstGetDevice',
                Text: 1
            }
        )
    );

    for (const item of powerCache) {
        const uid =
            uidString(item.UID);

        if (uid) {
            await mirrorObject(
                CFG.base +
                '.PowerDevices.' +
                uid,
                item
            );
        }
    }

    await writeState(
        CFG.base + '.System.PowerDeviceCount',
        powerCache.length
    );

    return powerCache;
}

async function readServiceState() {
    const data = await panelCommand(
        'ccCMDAPPServiceRequestState',
        {
            SubCmd: 'cstAll',
            option: 0
        }
    );

    await mirrorObject(
        CFG.base + '.ServiceState',
        data
    );

    return data;
}

function normalizeInputFields(item) {
    const out =
        Object.assign(
            {},
            item
        );

    if (
        out.ShortCircuit === undefined &&
        out.SortCircuit !== undefined
    ) {
        out.ShortCircuit =
            out.SortCircuit;
    }

    return out;
}

async function mirrorSensorList(
    branch,
    list,
    descriptor
) {
    for (const raw of list) {
        const item =
            normalizeInputFields(raw);

        const uid =
            String(item.UID);

        const base =
            CFG.base +
            '.' +
            branch +
            '.' +
            uid;

        let changed = await mirrorObject(
            base,
            item
        );

        await ensureString(
            base + '.PartitionUID',
            'Partition UID',
            ''
        );

        await ensureString(
            base + '.PartitionName',
            'Partition Name',
            ''
        );

        await ensureString(
            base + '.DetectorGroupUID',
            'Detector Group UID',
            ''
        );

        await ensureString(
            base + '.DetectorGroupName',
            'Detector Group Name',
            ''
        );

        await ensureString(
            base + '.LastUpdate',
            'Letztes Update',
            ''
        );

        if (await writeState(
            base + '.PartitionUID',
            descriptor.partitionUID
        )) {
            changed = true;
        }

        if (await writeState(
            base + '.PartitionName',
            descriptor.partitionName
        )) {
            changed = true;
        }

        if (await writeState(
            base + '.DetectorGroupUID',
            descriptor.groupUID
        )) {
            changed = true;
        }

        if (await writeState(
            base + '.DetectorGroupName',
            descriptor.groupName
        )) {
            changed = true;
        }

        let lastUpdate = null;
        try {
            lastUpdate = getState(base + '.LastUpdate');
        } catch (e) {
            lastUpdate = null;
        }

        // LastUpdate nur bei einer echten Sensor-/Zuordnungsänderung aktualisieren.
        if (changed || !lastUpdate || !lastUpdate.val) {
            await writeState(
                base + '.LastUpdate',
                nowIso()
            );
        }
    }
}

async function setGroupLiveTypes(descriptor) {
    const base =
        CFG.base +
        '.DetectorGroups.' +
        descriptor.groupUID +
        '.Live';

    await ensureBoolean(
        base + '.HasInputs',
        'Gruppe hat Inputs',
        false
    );

    await ensureBoolean(
        base + '.HasPIRs',
        'Gruppe hat PIRs',
        false
    );

    await ensureBoolean(
        base + '.HasSmoke',
        'Gruppe hat Rauchmelder',
        false
    );

    await writeState(
        base + '.HasInputs',
        !!descriptor.hasInputs
    );

    await writeState(
        base + '.HasPIRs',
        !!descriptor.hasPIRs
    );

    await writeState(
        base + '.HasSmoke',
        !!descriptor.hasSmokes
    );
}

async function queryInputStates(descriptor) {
    const data = await panelCommand(
        'ccCMDAPPInputStates',
        {
            ExecutorUIDs:
                descriptor.memberUIDs.join(','),
            Owner:
                descriptor.groupUID,
            Partition:
                descriptor.partitionUID,
            VDPeripheral: 1,
            Text: 1
        }
    );

    const list =
        normalizeList(data);

    await mirrorSensorList(
        'Inputs',
        list,
        descriptor
    );

    return list;
}

async function queryPIRStates(descriptor) {
    const data = await panelCommand(
        'ccCMDAPPPIRStates',
        {
            ExecutorUIDs:
                descriptor.memberUIDs.join(','),
            Owner:
                descriptor.groupUID,
            Partition:
                descriptor.partitionUID,
            VDPeripheral: 1,
            Text: 0
        }
    );

    const list =
        normalizeList(data);

    await mirrorSensorList(
        'PIRs',
        list,
        descriptor
    );

    return list;
}

async function querySmokeStates(descriptor) {
    const data = await panelCommand(
        'ccCMDAPPSmokeDetectorStates',
        {
            ExecutorUIDs:
                descriptor.memberUIDs.join(','),
            Owner:
                descriptor.groupUID,
            Partition:
                descriptor.partitionUID,
            VDPeripheral: 1,
            Text: 0
        }
    );

    const list =
        normalizeList(data);

    await mirrorSensorList(
        'SmokeDetectors',
        list,
        descriptor
    );

    return list;
}

/*
 * discoverTypes=true:
 * alle drei Endpunkte abfragen und Typen neu lernen.
 *
 * discoverTypes=false:
 * nur bereits sicher gefundene Typen abfragen.
 */
async function refreshDetectorGroup(
    descriptor,
    discoverTypes
) {
    const result = {
        inputUIDs: [],
        pirUIDs: [],
        smokeUIDs: []
    };

    if (
        !descriptor ||
        !descriptor.memberUIDs ||
        descriptor.memberUIDs.length === 0
    ) {
        return result;
    }

    if (
        paused ||
        stopping ||
        isLoginBlocked()
    ) {
        return result;
    }

    const doInputs =
        discoverTypes ||
        descriptor.hasInputs === true;

    const doPIRs =
        discoverTypes ||
        descriptor.hasPIRs === true;

    const doSmokes =
        discoverTypes ||
        descriptor.hasSmokes === true;

    if (doInputs) {
        try {
            const list =
                await queryInputStates(
                    descriptor
                );

            result.inputUIDs =
                list.map(
                    x => String(x.UID)
                );

            if (discoverTypes) {
                descriptor.hasInputs =
                    list.length > 0;
            }

        } catch (e) {
            if (
                isLoginBlockedError(e) ||
                isLoginRejectedError(e)
            ) {
                return result;
            }

            warn(
                'InputStates ' +
                descriptor.groupName +
                ': ' +
                e.message
            );
        }

        if (isLoginBlocked()) {
            return result;
        }

        await sleep(
            CFG.requestDelayMs
        );
    }

    if (doPIRs) {
        try {
            const list =
                await queryPIRStates(
                    descriptor
                );

            result.pirUIDs =
                list.map(
                    x => String(x.UID)
                );

            if (discoverTypes) {
                descriptor.hasPIRs =
                    list.length > 0;
            }

        } catch (e) {
            if (
                isLoginBlockedError(e) ||
                isLoginRejectedError(e)
            ) {
                return result;
            }

            warn(
                'PIRStates ' +
                descriptor.groupName +
                ': ' +
                e.message
            );
        }

        if (isLoginBlocked()) {
            return result;
        }

        await sleep(
            CFG.requestDelayMs
        );
    }

    if (doSmokes) {
        try {
            const list =
                await querySmokeStates(
                    descriptor
                );

            result.smokeUIDs =
                list.map(
                    x => String(x.UID)
                );

            if (discoverTypes) {
                descriptor.hasSmokes =
                    list.length > 0;
            }

        } catch (e) {
            if (
                !isLoginBlockedError(e) &&
                !isLoginRejectedError(e)
            ) {
                warn(
                    'SmokeDetectorStates ' +
                    descriptor.groupName +
                    ': ' +
                    e.message
                );
            }
        }
    }

    if (
        discoverTypes &&
        !isLoginBlocked()
    ) {
        await setGroupLiveTypes(
            descriptor
        );
    }

    return result;
}

async function waitForRefreshIdle(maxWaitMs) {
    const started =
        Date.now();

    while (refreshRunning) {
        if (
            paused ||
            stopping ||
            isLoginBlocked()
        ) {
            return false;
        }

        if (
            Date.now() - started >=
            maxWaitMs
        ) {
            return false;
        }

        await sleep(100);
    }

    return true;
}

async function refreshOperationalStates(reason) {
    if (
        paused ||
        stopping ||
        isLoginBlocked()
    ) {
        return false;
    }

    if (!sid) {
        await login();
    }

    const partitions =
        await readPartitions();

    for (const partition of partitions) {
        if (
            paused ||
            stopping ||
            isLoginBlocked()
        ) {
            return false;
        }

        await readDetectorGroups(
            partition
        );

        await sleep(
            CFG.requestDelayMs
        );
    }

    await refreshOutputStates();

    await writeState(
        CFG.base + '.System.LastStateRefresh',
        nowIso()
    );

    await writeState(
        CFG.base + '.System.LastRefreshReason',
        String(
            reason ||
            'Betriebsstatus'
        )
    );

    return true;
}

async function refreshAllDetectorStates(
    reason,
    discoverTypes
) {
    if (
        paused ||
        stopping ||
        isLoginBlocked()
    ) {
        return false;
    }

    if (
        writeRunning &&
        !discoverTypes
    ) {
        refreshPending = true;
        return false;
    }

    if (refreshRunning) {
        refreshPending = true;
        return false;
    }

    refreshRunning = true;

    try {
        if (!sid) {
            await login();
        }

        /*
         * Bei Ereignis-Refresh zuerst
         * Bereichs-/Gruppen-/Ausgangszustände aktualisieren.
         *
         * Genau dort liegen:
         * Alarm, at..., Release, Bypass und OmitType.
         */
        if (!discoverTypes) {
            await refreshOperationalStates(
                reason
            );

            if (
                paused ||
                stopping ||
                isLoginBlocked()
            ) {
                return false;
            }
        }

        const inputs =
            new Set();

        const pirs =
            new Set();

        const smokes =
            new Set();

        for (
            const descriptor
            of detectorGroups
        ) {
            if (
                paused ||
                stopping ||
                isLoginBlocked()
            ) {
                break;
            }

            if (
                !discoverTypes &&
                !descriptor.hasInputs &&
                !descriptor.hasPIRs &&
                !descriptor.hasSmokes
            ) {
                continue;
            }

            const r =
                await refreshDetectorGroup(
                    descriptor,
                    !!discoverTypes
                );

            r.inputUIDs.forEach(
                uid => inputs.add(uid)
            );

            r.pirUIDs.forEach(
                uid => pirs.add(uid)
            );

            r.smokeUIDs.forEach(
                uid => smokes.add(uid)
            );

            await sleep(
                CFG.requestDelayMs
            );
        }

        if (
            !paused &&
            !stopping &&
            !isLoginBlocked()
        ) {
            if (discoverTypes) {
                await writeState(
                    CFG.base + '.System.InputCount',
                    inputs.size
                );

                await writeState(
                    CFG.base + '.System.PIRCount',
                    pirs.size
                );

                await writeState(
                    CFG.base + '.System.SmokeCount',
                    smokes.size
                );
            }

            await writeState(
                CFG.base + '.System.LastStateRefresh',
                nowIso()
            );

            await writeState(
                CFG.base + '.System.LastRefreshReason',
                String(reason || '')
            );
        }

        return true;

    } catch (e) {
        if (
            !isLoginBlockedError(e) &&
            !isLoginRejectedError(e)
        ) {
            await handleError(
                'Status-Refresh',
                e
            );
        }

    } finally {
        refreshRunning = false;

        if (
            refreshPending &&
            !paused &&
            !stopping &&
            !isLoginBlocked() &&
            !writeRunning
        ) {
            refreshPending = false;

            setTimeout(
                () =>
                    refreshAllDetectorStates(
                        'nachgeholter Refresh',
                        false
                    ),
                100
            );

        } else if (!writeRunning) {
            refreshPending = false;
        }
    }
}


/***********************************************************************
 * VERIFIZIERTER SCHREIBZUGRIFF
 ***********************************************************************/

function isWriteEnabled() {
    const st =
        getState(
            CFG.base +
            '.Control.Write.Enabled'
        );

    return !!(
        st &&
        st.val === true
    );
}

async function waitForOperationalIdle(maxWaitMs) {
    const started =
        Date.now();

    while (
        fullSyncRunning ||
        refreshRunning
    ) {
        if (
            paused ||
            stopping ||
            isLoginBlocked()
        ) {
            return false;
        }

        if (
            Date.now() - started >=
            maxWaitMs
        ) {
            return false;
        }

        await sleep(100);
    }

    return true;
}

function validateWriteTarget(
    command,
    uid
) {
    const rules = {
        PARTITION_CLEAR:
            INVENTORY.partitions,

        PARTITION_UNSET:
            INVENTORY.partitions,

        PARTITION_PARTSET:
            INVENTORY.partitions,

        PARTITION_FULLSET:
            INVENTORY.partitions,

        OUTPUT_OFF:
            INVENTORY.normalOutputs,

        OUTPUT_ON:
            INVENTORY.normalOutputs,

        GROUP_BYPASS_ON:
            INVENTORY.groups,

        GROUP_BYPASS_OFF:
            INVENTORY.groups,

        GROUP_OMIT_PART:
            INVENTORY.groups,

        GROUP_UNOMIT_PART:
            INVENTORY.groups,

        GROUP_OMIT_ALWAYS:
            INVENTORY.groups,

        GROUP_UNOMIT_ALWAYS:
            INVENTORY.groups
    };

    if (
        !Object.prototype.hasOwnProperty.call(
            rules,
            command
        )
    ) {
        throw new Error(
            'Unbekannter oder nicht freigegebener Schreibbefehl: ' +
            command
        );
    }

    if (
        !uid ||
        !rules[command].has(uid)
    ) {
        throw new Error(
            'Ziel-UID ' +
            uid +
            ' gehört nicht zum für ' +
            command +
            ' entdeckten Inventar.'
        );
    }
}

function groupDescriptorByUID(uid) {
    return detectorGroups.find(
        d => d.groupUID === uid
    ) || null;
}

async function readPartitionByUID(uid) {
    const data = await panelCommand(
        'ccCMDAPPPartitionStates',
        {
            ExecutorUIDs: uid,
            Text: 1
        }
    );

    const item =
        findByUID(
            normalizeList(data),
            uid
        );

    if (!item) {
        throw new Error(
            'Bereich UID ' +
            uid +
            ' wurde beim Readback nicht geliefert.'
        );
    }

    await mirrorObject(
        CFG.base +
        '.Partitions.' +
        uid,
        item
    );

    await mirrorPartitionAlarmClasses(
        item
    );

    const idx =
        partitionsCache.findIndex(
            x =>
                uidString(x.UID) ===
                uid
        );

    if (idx >= 0) {
        partitionsCache[idx] =
            item;
    }

    return item;
}

async function readGroupByUID(uid) {
    const descriptor =
        groupDescriptorByUID(uid);

    if (!descriptor) {
        throw new Error(
            'Meldergruppe UID ' +
            uid +
            ' hat keinen bekannten Bereich.'
        );
    }

    const data = await panelCommand(
        'ccCMDAPPDetectorGroupStates',
        {
            Partition:
                descriptor.partitionUID,

            ExecutorUIDs:
                uid,

            Text:
                1
        }
    );

    const item =
        findByUID(
            normalizeList(data),
            uid
        );

    if (!item) {
        throw new Error(
            'Meldergruppe UID ' +
            uid +
            ' wurde beim Readback nicht geliefert.'
        );
    }

    const base =
        CFG.base +
        '.DetectorGroups.' +
        uid;

    await mirrorObject(
        base,
        item
    );

    await mirrorGroupSemantics(
        item
    );

    await ensureString(
        base + '.PartitionUID',
        'Partition UID',
        ''
    );

    await writeState(
        base + '.PartitionUID',
        descriptor.partitionUID
    );

    return item;
}

async function readNormalOutputByUID(uid) {
    const data = await panelCommand(
        'ccCMDAPPOutputStates',
        {
            ExecutorUIDs:
                uid
        }
    );

    const item =
        findByUID(
            normalizeList(data),
            uid
        );

    if (!item) {
        throw new Error(
            'Ausgang UID ' +
            uid +
            ' wurde beim Readback nicht geliefert.'
        );
    }

    await mirrorObject(
        CFG.base +
        '.Outputs.' +
        uid,
        item
    );

    return item;
}

async function sendOperationalWrite(
    command,
    uid
) {
    switch (command) {

        case 'PARTITION_CLEAR':
            return panelCommand(
                'ccCMDAPPPartition',
                {
                    SubCmd:
                        'cstClearSupervisor',

                    SetState:
                        'pssUnset',

                    ExecutorUID:
                        uid
                }
            );

        case 'PARTITION_UNSET':
            return panelCommand(
                'ccCMDAPPPartitionSetState',
                {
                    SetState:
                        'pssUnset',

                    ExecutorUID:
                        uid
                }
            );

        case 'PARTITION_PARTSET':
            return panelCommand(
                'ccCMDAPPPartitionSetState',
                {
                    SetState:
                        'pssPartSet',

                    ExecutorUID:
                        uid,

                    Mode:
                        0
                }
            );

        case 'PARTITION_FULLSET':
            return panelCommand(
                'ccCMDAPPPartitionSetState',
                {
                    SetState:
                        'pssFullSet',

                    ExecutorUID:
                        uid
                }
            );

        case 'OUTPUT_OFF':
            return panelCommand(
                'ccCMDAPPOutput',
                {
                    SubCmd:
                        'cstOff',

                    ExecutorUID:
                        uid,

                    option:
                        0
                }
            );

        case 'OUTPUT_ON':
            return panelCommand(
                'ccCMDAPPOutput',
                {
                    SubCmd:
                        'cstOn',

                    ExecutorUID:
                        uid,

                    option:
                        0
                }
            );

        case 'GROUP_BYPASS_ON':
            return panelCommand(
                'ccCMDAPPPartitionMember',
                {
                    SubCmd:
                        'cstBypassOn',

                    ExecutorUID:
                        uid
                }
            );

        case 'GROUP_BYPASS_OFF':
            return panelCommand(
                'ccCMDAPPPartitionMember',
                {
                    SubCmd:
                        'cstBypassOff',

                    ExecutorUID:
                        uid
                }
            );

        case 'GROUP_OMIT_PART':
            return panelCommand(
                'ccCMDAPPPartitionMemberOmit',
                {
                    ExecutorUID:
                        uid,

                    OmitType:
                        'otPartSet'
                }
            );

        case 'GROUP_UNOMIT_PART':
            return panelCommand(
                'ccCMDAPPPartitionMemberOmit',
                {
                    ExecutorUID:
                        uid,

                    OmitType:
                        'otUnOmitPartSet'
                }
            );

        case 'GROUP_OMIT_ALWAYS':
            return panelCommand(
                'ccCMDAPPPartitionMemberOmit',
                {
                    ExecutorUID:
                        uid,

                    OmitType:
                        'otAlways'
                }
            );

        case 'GROUP_UNOMIT_ALWAYS':
            return panelCommand(
                'ccCMDAPPPartitionMemberOmit',
                {
                    ExecutorUID:
                        uid,

                    OmitType:
                        'otUnOmitAlways'
                }
            );

        default:
            throw new Error(
                'Nicht implementierter Schreibbefehl: ' +
                command
            );
    }
}

async function validateOperationalPreconditions(
    command,
    uid
) {
    if (command === 'PARTITION_CLEAR') {
        const partition =
            await readPartitionByUID(uid);

        if (
            String(partition.SetState) !==
            'pssUnset'
        ) {
            throw new Error(
                'PARTITION_CLEAR ist nur im experimentell bestätigten Zustand pssUnset freigegeben. Aktuell=' +
                valueOrEmpty(
                    partition.SetState
                )
            );
        }

        return;
    }

    if (command === 'GROUP_BYPASS_ON') {
        const group =
            await readGroupByUID(uid);

        const descriptor =
            groupDescriptorByUID(uid);

        if (!descriptor) {
            throw new Error(
                'Keine Bereichszuordnung für Meldergruppe ' +
                uid +
                '.'
            );
        }

        const partition =
            await readPartitionByUID(
                descriptor.partitionUID
            );

        if (
            flagValue(group.Alarm)
        ) {
            throw new Error(
                'GROUP_BYPASS_ON abgelehnt: Meldergruppe ' +
                uid +
                ' steht bereits im Alarm. Alarme werden nicht übergangen.'
            );
        }

        if (
            String(partition.SetState) !==
            'pssUnset'
        ) {
            throw new Error(
                'GROUP_BYPASS_ON ist nur im experimentell bestätigten unscharfen Zustand freigegeben. Aktuell=' +
                valueOrEmpty(
                    partition.SetState
                )
            );
        }
    }
}

function responseResultText(response) {
    if (
        !response ||
        typeof response !== 'object' ||
        response.Result === undefined
    ) {
        return 'kein Result-Feld';
    }

    return String(
        response.Result
    );
}

async function verifyOperationalWrite(
    command,
    uid
) {
    let last = null;
    let detail = '';

    for (
        let attempt = 1;
        attempt <= CFG.writeVerifyTries;
        attempt++
    ) {
        await sleep(
            CFG.writeVerifyDelayMs
        );

        if (
            command === 'PARTITION_CLEAR'
        ) {
            last =
                await readPartitionByUID(
                    uid
                );

            const ok =
                !flagValue(
                    last.Alarm
                );

            detail =
                'Alarm=' +
                valueOrEmpty(last.Alarm) +
                ', SetState=' +
                valueOrEmpty(last.SetState) +
                ', activeTypes=' +
                activeAlarmTypeNames(last)
                    .join(',');

            if (ok) {
                return {
                    verified: true,
                    detail,
                    state: last
                };
            }

        } else if (
            command === 'PARTITION_UNSET' ||
            command === 'PARTITION_PARTSET' ||
            command === 'PARTITION_FULLSET'
        ) {
            const expected =
                command === 'PARTITION_UNSET'
                    ? 'pssUnset'
                    : command === 'PARTITION_PARTSET'
                        ? 'pssPartSet'
                        : 'pssFullSet';

            last =
                await readPartitionByUID(
                    uid
                );

            detail =
                'SetState=' +
                valueOrEmpty(last.SetState) +
                ', erwartet=' +
                expected +
                ', Alarm=' +
                valueOrEmpty(last.Alarm);

            if (
                String(last.SetState) ===
                expected
            ) {
                return {
                    verified: true,
                    detail,
                    state: last
                };
            }

        } else if (
            command === 'OUTPUT_ON' ||
            command === 'OUTPUT_OFF'
        ) {
            const expected =
                command === 'OUTPUT_ON';

            last =
                await readNormalOutputByUID(
                    uid
                );

            detail =
                'On=' +
                valueOrEmpty(last.On) +
                ', erwartet=' +
                (
                    expected
                        ? '1'
                        : '0'
                );

            if (
                flagValue(last.On) ===
                expected
            ) {
                return {
                    verified: true,
                    detail,
                    state: last
                };
            }

        } else {
            last =
                await readGroupByUID(
                    uid
                );

            if (
                command === 'GROUP_BYPASS_ON' ||
                command === 'GROUP_BYPASS_OFF'
            ) {
                const expected =
                    command ===
                    'GROUP_BYPASS_ON';

                detail =
                    'Bypass=' +
                    valueOrEmpty(last.Bypass) +
                    ', erwartet=' +
                    (
                        expected
                            ? '1'
                            : '0'
                    ) +
                    ', Release=' +
                    valueOrEmpty(last.Release) +
                    ', Alarm=' +
                    valueOrEmpty(last.Alarm);

                if (
                    flagValue(last.Bypass) ===
                    expected
                ) {
                    const descriptor =
                        groupDescriptorByUID(
                            uid
                        );

                    if (descriptor) {
                        await readPartitionByUID(
                            descriptor.partitionUID
                        );
                    }

                    return {
                        verified: true,
                        detail,
                        state: last
                    };
                }

            } else {
                const actualOmitType =
                    String(
                        last.OmitType ||
                        'otNone'
                    );

                const internalBlocked =
                    actualOmitType === 'otPartSet' ||
                    actualOmitType === 'otAlwaysPartSet';

                const externalBlocked =
                    actualOmitType === 'otAlways' ||
                    actualOmitType === 'otAlwaysPartSet';

                let verifiedOmit = false;
                let expectedText = '';

                switch (command) {
                    case 'GROUP_OMIT_PART':
                        verifiedOmit = internalBlocked;
                        expectedText = 'intern gesperrt';
                        break;

                    case 'GROUP_UNOMIT_PART':
                        verifiedOmit = !internalBlocked;
                        expectedText = 'intern nicht gesperrt';
                        break;

                    case 'GROUP_OMIT_ALWAYS':
                        verifiedOmit = externalBlocked;
                        expectedText = 'extern gesperrt';
                        break;

                    case 'GROUP_UNOMIT_ALWAYS':
                        verifiedOmit = !externalBlocked;
                        expectedText = 'extern nicht gesperrt';
                        break;

                    default:
                        verifiedOmit = false;
                        expectedText = 'unbekannter Sperrbefehl';
                }

                detail =
                    'OmitType=' +
                    valueOrEmpty(last.OmitType) +
                    ', erwartet=' +
                    expectedText +
                    ', intern=' +
                    (internalBlocked ? '1' : '0') +
                    ', extern=' +
                    (externalBlocked ? '1' : '0');

                if (verifiedOmit) {
                    const descriptor =
                        groupDescriptorByUID(
                            uid
                        );

                    if (descriptor) {
                        await readPartitionByUID(
                            descriptor.partitionUID
                        );
                    }

                    return {
                        verified: true,
                        detail,
                        state: last
                    };
                }
            }
        }
    }

    return {
        verified: false,
        detail,
        state: last
    };
}

async function executeWriteFromControl() {
    if (writeRunning) {
        throw new Error(
            'Es läuft bereits ein Schreibbefehl.'
        );
    }

    if (paused) {
        throw new Error(
            'Schreibzugriff während Pause gesperrt.'
        );
    }

    if (stopping) {
        throw new Error(
            'Skript wird beendet.'
        );
    }

    if (isLoginBlocked()) {
        throw new Error(
            'Login-Sicherheitswartezeit aktiv.'
        );
    }

    if (!isWriteEnabled()) {
        throw new Error(
            'Control.Write.Enabled ist AUS.'
        );
    }

    const commandState =
        getState(
            CFG.base +
            '.Control.Write.Command'
        );

    const uidState =
        getState(
            CFG.base +
            '.Control.Write.TargetUID'
        );

    const command =
        commandState &&
        commandState.val !== null
            ? String(
                commandState.val
            )
                .trim()
                .toUpperCase()
            : '';

    const uid =
        uidString(
            uidState &&
            uidState.val
        );

    validateWriteTarget(
        command,
        uid
    );

    writeRunning = true;

    await writeState(
        CFG.base + '.Control.Write.Busy',
        true
    );

    await writeState(
        CFG.base + '.Control.Write.LastVerified',
        false
    );

    await writeState(
        CFG.base + '.Control.Write.LastVerification',
        ''
    );

    try {
        const idle =
            await waitForOperationalIdle(
                CFG.writeIdleWaitMs
            );

        if (!idle) {
            throw new Error(
                'System wurde vor Schreibbefehl nicht rechtzeitig frei.'
            );
        }

        validateWriteTarget(
            command,
            uid
        );

        await writeState(
            CFG.base + '.Control.Write.LastCommand',
            command +
            ' ' +
            uid
        );

        await writeState(
            CFG.base + '.Control.Write.LastError',
            ''
        );

        await writeState(
            CFG.base + '.Control.Write.LastTime',
            nowIso()
        );

        if (!sid) {
            await login();
        }

        await validateOperationalPreconditions(
            command,
            uid
        );

        const response =
            await sendOperationalWrite(
                command,
                uid
            );

        const resultText =
            responseResultText(
                response
            );

        await writeState(
            CFG.base + '.Control.Write.LastResult',
            response &&
            typeof response === 'object'
                ? safeJson(response)
                : 'REQUEST_SENT'
        );

        /*
         * Absichtlich nicht blind auf Result=OK vertrauen:
         *
         * Clear/Unset können im bereits erreichten Zustand
         * Result=Failed liefern.
         *
         * Umgekehrt kann Result=OK kommen, ohne dass der
         * gewünschte Endzustand tatsächlich erreicht wurde.
         *
         * Deshalb entscheidet ausschließlich der Readback.
         */
        if (
            resultText !== 'OK' &&
            resultText !== 'kein Result-Feld'
        ) {
            warn(
                'Schreibantwort ' +
                command +
                ' UID=' +
                uid +
                ' meldet Result=' +
                resultText +
                '; Readback entscheidet.'
            );
        }

        const verification =
            await verifyOperationalWrite(
                command,
                uid
            );

        await writeState(
            CFG.base + '.Control.Write.LastVerification',
            verification.detail
        );

        await writeState(
            CFG.base + '.Control.Write.LastVerified',
            verification.verified
        );

        if (!verification.verified) {
            throw new Error(
                command +
                ' UID=' +
                uid +
                ' konnte per Readback NICHT bestätigt werden. ' +
                verification.detail
            );
        }

        info(
            'Schreibbefehl per Readback bestätigt: ' +
            command +
            ' UID=' +
            uid +
            ' | ' +
            verification.detail
        );

        await refreshOperationalStates(
            'nach Write ' +
            command
        );

    } catch (e) {
        await writeState(
            CFG.base + '.Control.Write.LastError',
            nowIso() +
            ' ' +
            e.message
        );

        throw e;

    } finally {
        writeRunning = false;

        await writeState(
            CFG.base + '.Control.Write.Busy',
            false
        );

        if (
            refreshPending &&
            !paused &&
            !stopping &&
            !isLoginBlocked()
        ) {
            refreshPending = false;

            setTimeout(
                () =>
                    refreshAllDetectorStates(
                        'nach Write nachgeholter Refresh',
                        false
                    ),
                100
            );
        }
    }
}

async function fullSync(reason) {
    if (
        paused ||
        stopping ||
        isLoginBlocked() ||
        writeRunning
    ) {
        return;
    }

    if (fullSyncRunning) {
        dbg(
            'FullSync bereits aktiv.'
        );
        return;
    }

    fullSyncRunning = true;

    try {
        info(
            'FullSync gestartet: ' +
            reason
        );

        if (!sid) {
            await login();
        }

        detectorGroups = [];

        clearInventory();

        const partitions =
            await readPartitions();

        let totalGroups = 0;
        let totalMemberEntries = 0;

        for (
            const partition
            of partitions
        ) {
            if (
                paused ||
                stopping ||
                isLoginBlocked()
            ) {
                break;
            }

            const groups =
                await readDetectorGroups(
                    partition
                );

            totalGroups +=
                groups.length;

            for (
                const group
                of groups
            ) {
                if (
                    paused ||
                    stopping ||
                    isLoginBlocked()
                ) {
                    break;
                }

                const members =
                    await readDetectorMembers(
                        partition,
                        group
                    );

                totalMemberEntries +=
                    members.length;

                detectorGroups.push({
                    partitionUID:
                        String(partition.UID),

                    partitionName:
                        valueOrEmpty(
                            partition.Name
                        ),

                    groupUID:
                        String(group.UID),

                    groupName:
                        valueOrEmpty(
                            group.Name
                        ),

                    memberUIDs:
                        members
                            .filter(
                                x =>
                                    x &&
                                    x.UID !== undefined
                            )
                            .map(
                                x =>
                                    String(x.UID)
                            ),

                    hasInputs: false,
                    hasPIRs: false,
                    hasSmokes: false
                });

                await sleep(
                    CFG.requestDelayMs
                );
            }
        }

        if (
            paused ||
            stopping ||
            isLoginBlocked()
        ) {
            return;
        }

        await writeState(
            CFG.base + '.System.DetectorGroupCount',
            totalGroups
        );

        await writeState(
            CFG.base + '.System.DetectorMemberCount',
            totalMemberEntries
        );

        const refreshIdle =
            await waitForRefreshIdle(
                30000
            );

        if (!refreshIdle) {
            if (
                !paused &&
                !stopping &&
                !isLoginBlocked()
            ) {
                throw new Error(
                    'FullSync: laufender Status-Refresh wurde innerhalb von 30 s nicht beendet.'
                );
            }

            return;
        }

        const discoveryDone =
            await refreshAllDetectorStates(
                'FullSync',
                true
            );

        if (
            !discoveryDone ||
            paused ||
            stopping ||
            isLoginBlocked()
        ) {
            return;
        }

        const liveGroupCount =
            detectorGroups.filter(
                d =>
                    d.hasInputs ||
                    d.hasPIRs ||
                    d.hasSmokes
            ).length;

        await writeState(
            CFG.base + '.System.LiveGroupCount',
            liveGroupCount
        );

        await readOutputsInventory();
        await readMacrosInventory();
        await readUsersInventory();
        await readPowerInventory();
        await readServiceState();

        await writeState(
            CFG.base + '.System.LastFullSync',
            nowIso()
        );

        info(
            'FullSync erfolgreich: ' +
            partitions.length +
            ' Bereiche, ' +
            totalGroups +
            ' Meldergruppen, ' +
            totalMemberEntries +
            ' Member-Zuordnungen, ' +
            liveGroupCount +
            ' Gruppen mit Live-State, ' +
            outputsCache.length +
            ' Ausgänge, ' +
            macrosCache.length +
            ' Makros, ' +
            usersCache.length +
            ' Benutzer, ' +
            powerCache.length +
            ' Netzteile'
        );

    } catch (e) {
        if (
            !isLoginBlockedError(e) &&
            !isLoginRejectedError(e)
        ) {
            await handleError(
                'FullSync',
                e
            );
        }

    } finally {
        fullSyncRunning = false;
    }
}

async function keepalive() {
    if (
        paused ||
        stopping ||
        !sid ||
        isLoginBlocked() ||
        writeRunning
    ) {
        return;
    }

    try {
        await panelCommand(
            'ccCMDAPPISOMDateTime',
            {
                SubCmd: 'cstGet',
                option: 0
            }
        );

    } catch (e) {
        if (
            !isLoginBlockedError(e) &&
            !isLoginRejectedError(e)
        ) {
            await handleError(
                'Keepalive',
                e
            );
        }
    }
}

async function pollConfigInfo() {
    if (
        paused ||
        stopping ||
        isLoginBlocked() ||
        writeRunning
    ) {
        return;
    }

    try {
        const data =
            await panelCommand(
                'ccCMDAPPISOMGetInfo',
                {
                    SubCmd: 'cstConfigInfo',
                    option: 0
                }
            );

        if (
            !data ||
            data.ChangeCounter === undefined
        ) {
            return;
        }

        const counter =
            Number(
                data.ChangeCounter
            );

        if (!Number.isFinite(counter)) {
            warn(
                'Ungültiger ChangeCounter: ' +
                String(data.ChangeCounter)
            );
            return;
        }

        await writeState(
            CFG.base + '.System.ChangeCounter',
            counter
        );

        if (
            lastChangeCounter === null
        ) {
            lastChangeCounter =
                counter;

        } else if (
            counter !==
            lastChangeCounter
        ) {
            info(
                'ChangeCounter geändert: ' +
                lastChangeCounter +
                ' -> ' +
                counter
            );

            lastChangeCounter =
                counter;

            await fullSync(
                'ChangeCounter geändert'
            );
        }

    } catch (e) {
        if (
            !isLoginBlockedError(e) &&
            !isLoginRejectedError(e)
        ) {
            await handleError(
                'ConfigPoll',
                e
            );
        }
    }
}

function stopSSEConnectionOnly() {
    if (sseRequest) {
        try {
            sseRequest.destroy();
        } catch (e) {
            // ignorieren
        }

        sseRequest = null;
    }
}

function stopSSE() {
    if (sseReconnectTimer) {
        clearTimeout(
            sseReconnectTimer
        );

        sseReconnectTimer = null;
    }

    stopSSEConnectionOnly();
}

function scheduleSSEReconnect() {
    if (
        paused ||
        stopping
    ) {
        return;
    }

    if (isLoginBlocked()) {
        scheduleLoginAfterBlock();
        return;
    }

    if (sseReconnectTimer) {
        return;
    }

    sseReconnectTimer =
        setTimeout(
            async () => {
                sseReconnectTimer =
                    null;

                if (
                    paused ||
                    stopping
                ) {
                    return;
                }

                if (isLoginBlocked()) {
                    scheduleLoginAfterBlock();
                    return;
                }

                try {
                    if (!sid) {
                        await login();
                    }

                    startSSE();

                } catch (e) {
                    if (
                        isLoginBlockedError(e) ||
                        isLoginRejectedError(e)
                    ) {
                        return;
                    }

                    await handleError(
                        'SSE Reconnect',
                        e
                    );

                    scheduleSSEReconnect();
                }
            },
            CFG.sseReconnectMs
        );
}

function scheduleEventRefresh(eventName) {
    if (
        paused ||
        stopping ||
        isLoginBlocked() ||
        writeRunning
    ) {
        return;
    }

    if (eventRefreshTimer) {
        clearTimeout(
            eventRefreshTimer
        );
    }

    eventRefreshTimer =
        setTimeout(
            () => {
                eventRefreshTimer =
                    null;

                if (
                    !paused &&
                    !stopping &&
                    !isLoginBlocked() &&
                    !writeRunning
                ) {
                    refreshAllDetectorStates(
                        'SSE ' +
                        eventName,
                        false
                    );
                }
            },
            CFG.eventRefreshDelayMs
        );
}

function startSSE() {
    if (
        paused ||
        stopping ||
        !sid ||
        isLoginBlocked()
    ) {
        return;
    }

    stopSSE();

    const options = {
        hostname: CFG.host,
        port: CFG.port,
        path: '/panel/events',
        method: 'GET',
        rejectUnauthorized: false,
        headers: {
            Accept: 'text/event-stream',
            'Cache-Control': 'no-cache',
            Connection: 'keep-alive',
            'X-My-SID': sid
        }
    };

    let buffer = '';
    let currentEvent = '';
    let currentData = '';

    const req =
        https.request(
            options,
            res => {
                if (
                    res.statusCode === 401
                ) {
                    warn(
                        'SSE Session ungültig.'
                    );

                    sid = null;
                    generatorUID = null;

                    writeState(
                        CFG.base + '.System.SessionActive',
                        false
                    );

                    writeState(
                        CFG.base + '.System.Connected',
                        false
                    );

                    res.resume();

                    sseRequest = null;

                    scheduleSSEReconnect();

                    return;
                }

                if (
                    res.statusCode !== 200
                ) {
                    warn(
                        'SSE HTTP ' +
                        res.statusCode
                    );

                    res.resume();

                    sseRequest = null;

                    scheduleSSEReconnect();

                    return;
                }

                info(
                    'SSE verbunden'
                );

                res.setEncoding(
                    'utf8'
                );

                res.on(
                    'data',
                    chunk => {
                        buffer += chunk;

                        while (
                            buffer.indexOf('\n') >= 0
                        ) {
                            const pos =
                                buffer.indexOf('\n');

                            let line =
                                buffer.substring(
                                    0,
                                    pos
                                );

                            buffer =
                                buffer.substring(
                                    pos + 1
                                );

                            if (
                                line.endsWith('\r')
                            ) {
                                line =
                                    line.substring(
                                        0,
                                        line.length - 1
                                    );
                            }

                            if (
                                line.startsWith(':')
                            ) {
                                continue;
                            }

                            if (
                                line.startsWith('event:')
                            ) {
                                currentEvent =
                                    line
                                        .substring(6)
                                        .trim();

                                continue;
                            }

                            if (
                                line.startsWith('data:')
                            ) {
                                if (currentData) {
                                    currentData += '\n';
                                }

                                currentData +=
                                    line
                                        .substring(5)
                                        .trim();

                                continue;
                            }

                            if (line === '') {
                                const eventName =
                                    currentEvent ||
                                    'message';

                                writeState(
                                    CFG.base + '.System.LastSSEEvent',
                                    nowIso() +
                                    ' ' +
                                    eventName
                                );

                                dbg(
                                    'SSE Event: ' +
                                    eventName +
                                    (
                                        currentData
                                            ? ' ' + currentData
                                            : ''
                                    )
                                );

                                if (
                                    eventName ===
                                    'serviceStateUpdate'
                                ) {
                                    scheduleEventRefresh(
                                        eventName
                                    );
                                }

                                if (
                                    eventName ===
                                    'closedConnection'
                                ) {
                                    warn(
                                        'SSE closedConnection'
                                    );

                                    try {
                                        req.destroy();
                                    } catch (e) {
                                        // ignorieren
                                    }
                                }

                                currentEvent = '';
                                currentData = '';
                            }
                        }
                    }
                );

                res.on(
                    'end',
                    () => {
                        sseRequest = null;

                        if (
                            stopping ||
                            paused ||
                            isLoginBlocked()
                        ) {
                            return;
                        }

                        warn(
                            'SSE Verbindung beendet.'
                        );

                        scheduleSSEReconnect();
                    }
                );

                res.on(
                    'error',
                    err => {
                        sseRequest = null;

                        if (
                            stopping ||
                            paused ||
                            isLoginBlocked()
                        ) {
                            return;
                        }

                        warn(
                            'SSE Response Fehler: ' +
                            err.message
                        );

                        scheduleSSEReconnect();
                    }
                );
            }
        );

    sseRequest = req;

    req.on(
        'error',
        err => {
            sseRequest = null;

            if (
                stopping ||
                paused ||
                isLoginBlocked()
            ) {
                return;
            }

            warn(
                'SSE Fehler: ' +
                err.message
            );

            scheduleSSEReconnect();
        }
    );

    req.end();
}

function stopTimers() {
    if (keepaliveTimer) {
        clearInterval(
            keepaliveTimer
        );
        keepaliveTimer = null;
    }

    if (configPollTimer) {
        clearInterval(
            configPollTimer
        );
        configPollTimer = null;
    }

    if (fullSyncTimer) {
        clearInterval(
            fullSyncTimer
        );
        fullSyncTimer = null;
    }

    if (eventRefreshTimer) {
        clearTimeout(
            eventRefreshTimer
        );
        eventRefreshTimer = null;
    }

    stopSSE();
}

function startTimers() {
    stopTimers();

    if (isLoginBlocked()) {
        scheduleLoginAfterBlock();
        return;
    }

    keepaliveTimer =
        setInterval(
            keepalive,
            CFG.keepaliveMs
        );

    configPollTimer =
        setInterval(
            pollConfigInfo,
            CFG.configPollMs
        );

    fullSyncTimer =
        setInterval(
            () =>
                fullSync(
                    'periodischer FullSync'
                ),
            CFG.fullSyncMs
        );

    startSSE();
}

async function handleError(
    source,
    err
) {
    if (
        isLoginBlockedError(err) ||
        isLoginRejectedError(err)
    ) {
        return;
    }

    const message =
        source +
        ': ' +
        (
            err &&
            err.message
                ? err.message
                : String(err)
        );

    errorLog(
        message
    );

    await writeState(
        CFG.base + '.System.LastError',
        nowIso() +
        ' ' +
        message
    );
}

async function setPaused(value) {
    paused = !!value;

    if (paused) {
        info(
            'Pause aktiviert.'
        );

        stopTimers();

        clearLoginBlockTimer();

        await writeState(
            CFG.base + '.Control.Write.Enabled',
            false
        );

        await logout();

        return;
    }

    info(
        'Pause beendet.'
    );

    if (isLoginBlocked()) {
        info(
            'Login-Sicherheitswartezeit ist noch aktiv. Kein Loginversuch.'
        );

        scheduleLoginAfterBlock();

        return;
    }

    try {
        await login();

        await fullSync(
            'Pause beendet'
        );

        startTimers();

    } catch (e) {
        if (
            isLoginBlockedError(e) ||
            isLoginRejectedError(e)
        ) {
            return;
        }

        await handleError(
            'Pause Ende',
            e
        );

        scheduleSSEReconnect();
    }
}

on(
    {
        id:
            CFG.base +
            '.Control.Pause',

        change:
            'ne'
    },

    async obj => {
        if (
            !obj ||
            !obj.state
        ) {
            return;
        }

        await setPaused(
            !!obj.state.val
        );
    }
);

on(
    {
        id:
            CFG.base +
            '.Control.FullSync',

        change:
            'ne'
    },

    async obj => {
        if (
            !obj ||
            !obj.state ||
            obj.state.val !== true
        ) {
            return;
        }

        try {
            if (
                !paused &&
                !stopping &&
                !isLoginBlocked()
            ) {
                await fullSync(
                    'manuell'
                );
            }

        } finally {
            setState(
                CFG.base +
                '.Control.FullSync',
                false,
                true
            );
        }
    }
);

on(
    {
        id:
            CFG.base +
            '.Control.Write.Execute',

        change:
            'ne'
    },

    async obj => {
        if (
            !obj ||
            !obj.state ||
            obj.state.val !== true ||
            obj.state.ack === true
        ) {
            return;
        }

        try {
            await executeWriteFromControl();

        } catch (e) {
            errorLog(
                'Schreibbefehl abgelehnt/fehlgeschlagen: ' +
                e.message
            );

            await writeState(
                CFG.base + '.Control.Write.LastError',
                nowIso() +
                ' ' +
                e.message
            );

        } finally {
            setState(
                CFG.base +
                '.Control.Write.Execute',
                false,
                true
            );
        }
    }
);

async function start() {
    info(
        'Starte MB-Secure Auto Mirror 2.1.2 FINAL READ/WRITE'
    );

    await createSystemStates();

    /*
     * Nach JEDEM Scriptstart ist Schreiben aus.
     * Es muss vom Benutzer bewusst wieder freigegeben werden.
     */
    await writeState(
        CFG.base + '.Control.Write.Enabled',
        false
    );

    await writeState(
        CFG.base + '.Control.Write.Execute',
        false
    );

    await writeState(
        CFG.base + '.Control.Write.Busy',
        false
    );

    await writeState(
        CFG.base + '.Control.Write.LastVerified',
        false
    );

    await restoreLoginBlock();

    const pauseState =
        getState(
            CFG.base +
            '.Control.Pause'
        );

    paused =
        pauseState
            ? !!pauseState.val
            : false;

    if (paused) {
        info(
            'Control.Pause ist aktiv. Keine Verbindung zur Zentrale.'
        );
        return;
    }

    if (isLoginBlocked()) {
        scheduleLoginAfterBlock();
        return;
    }

    try {
        await login();

        await fullSync(
            'Scriptstart'
        );

        startTimers();

    } catch (e) {
        if (
            isLoginBlockedError(e) ||
            isLoginRejectedError(e)
        ) {
            return;
        }

        await handleError(
            'Scriptstart',
            e
        );

        scheduleSSEReconnect();
    }
}

onStop(
    async callback => {
        stopping = true;

        info(
            'MB-Secure Mirror wird beendet.'
        );

        stopTimers();
        clearLoginBlockTimer();

        try {
            await writeState(
                CFG.base + '.Control.Write.Enabled',
                false
            );
        } catch (e) {
            // ignorieren
        }

        try {
            await logout();
        } catch (e) {
            dbg(
                'Logout beim Stop: ' +
                e.message
            );
        }

        callback();
    },
    5000
);

start();