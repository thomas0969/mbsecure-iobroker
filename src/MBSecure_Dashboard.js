/***********************************************************************
 * MB-Secure VIS2 Dashboard
 *
 * Version: 1.3.1
 *
 * Voraussetzungen:
 * - MB-Secure AutoMirror v2.1.0 oder kompatibel
 * - VIS2 Material Widgets -> HTML-Vorlage
 *
 * HTML-Datenpunkt:
 * 0_userdata.0.MBSecure.Dashboard.HTML
 *
 * WICHTIG v1.3.0:
 * - KEIN <script>-Block im erzeugten HTML
 * - KEINE window.mbSec... Funktionen
 * - Bedienung direkt über vis.setValue(...) im HTML-Event
 * - serverseitige Sicherheitsprüfung bleibt erhalten
 * - Schreibbefehle gehen ausschließlich über Control.Write
 * - Dashboard spricht die MB-Secure niemals direkt an
 * - interne und externe Sperre sind unabhängig; otAlwaysPartSet = beide aktiv
 *
 * Layout:
 * - intrinsisch responsiv
 * - keine feste Desktopbreite
 * - kein horizontales Scrollen
 * - automatische Spaltenzahl mit auto-fit/minmax
 ***********************************************************************/


// =====================================================================
// KONFIGURATION
// =====================================================================

const VERSION = '1.3.1';

const ROOT = '0_userdata.0.MBSecure';
const DASH = `${ROOT}.Dashboard`;


// ---------------------------------------------------------------------
// Dashboard-Datenpunkte
// ---------------------------------------------------------------------

const DP_HTML = `${DASH}.HTML`;

const DP_ACTION = `${DASH}.Action`;

const DP_ACTION_RESULT = `${DASH}.ActionResult`;

const DP_LAST_ACTION = `${DASH}.LastAction`;

const DP_LAST_RENDER = `${DASH}.LastRender`;


// ---------------------------------------------------------------------
// MB-Secure Write-Control
// ---------------------------------------------------------------------

const WRITE = `${ROOT}.Control.Write`;

const WRITE_ENABLED = `${WRITE}.Enabled`;

const WRITE_COMMAND = `${WRITE}.Command`;

const WRITE_TARGET = `${WRITE}.TargetUID`;

const WRITE_EXECUTE = `${WRITE}.Execute`;

const WRITE_BUSY = `${WRITE}.Busy`;

const WRITE_VERIFIED = `${WRITE}.LastVerified`;

const WRITE_VERIFICATION = `${WRITE}.LastVerification`;

const WRITE_ERROR = `${WRITE}.LastError`;

const WRITE_LAST_COMMAND = `${WRITE}.LastCommand`;

const WRITE_LAST_TIME = `${WRITE}.LastTime`;


// ---------------------------------------------------------------------
// Erlaubte Dashboard-Kommandos
// ---------------------------------------------------------------------

const ALLOWED_COMMANDS = new Set([

    'PARTITION_CLEAR',

    'PARTITION_UNSET',

    'PARTITION_PARTSET',

    'PARTITION_FULLSET',

    'GROUP_BYPASS_ON',

    'GROUP_BYPASS_OFF',

    'GROUP_OMIT_PART',

    'GROUP_UNOMIT_PART',

    'GROUP_OMIT_ALWAYS',

    'GROUP_UNOMIT_ALWAYS'

]);


// ---------------------------------------------------------------------
// Laufzeit
// ---------------------------------------------------------------------

let renderTimer = null;

let actionRunning = false;


// =====================================================================
// GRUNDFUNKTIONEN
// =====================================================================

async function ensureState(
    id,
    def,
    type,
    name,
    write = false,
    role = null
) {

    if (existsState(id)) {
        return;
    }

    await createStateAsync(
        id,
        def,
        false,
        {
            name,

            type,

            role:
                role ||
                (
                    type === 'boolean'
                        ? 'indicator'
                        : type === 'number'
                            ? 'value'
                            : 'text'
                ),

            read: true,

            write
        }
    );
}


// ---------------------------------------------------------------------

async function stateVal(
    id,
    fallback = ''
) {

    try {

        const state =
            await getStateAsync(id);

        if (
            state &&
            state.val !== undefined &&
            state.val !== null
        ) {

            return state.val;
        }

    } catch (_) {

        // bewusst leer
    }

    return fallback;
}


// ---------------------------------------------------------------------
// Liest den ersten vorhandenen Datenpunkt aus einer Liste.
// Dadurch bleibt das Dashboard kompatibel mit alten und neuen
// Mirror-Strukturen.
// ---------------------------------------------------------------------

async function firstStateVal(
    ids,
    fallback = ''
) {

    for (const id of ids) {

        try {

            if (!existsState(id)) {
                continue;
            }

            const state =
                await getStateAsync(id);

            if (
                state &&
                state.val !== undefined &&
                state.val !== null
            ) {

                return state.val;
            }

        } catch (_) {

            // nächster Kandidat
        }
    }

    return fallback;
}


// ---------------------------------------------------------------------

function truthy(v) {

    if (typeof v === 'boolean') {
        return v;
    }

    if (typeof v === 'number') {
        return v !== 0;
    }

    const value =
        String(v ?? '')
            .trim()
            .toLowerCase();

    return [
        '1',
        'true',
        'on',
        'yes'
    ].includes(value);
}


// ---------------------------------------------------------------------
// HTML-Escaping
// ---------------------------------------------------------------------

function esc(v) {

    return String(v ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}


// ---------------------------------------------------------------------
// JS-String sicher erzeugen
// ---------------------------------------------------------------------

function jsString(v) {

    return JSON.stringify(
        String(v ?? '')
    );
}


// ---------------------------------------------------------------------
// JavaScript für HTML-Attribut escapen
// ---------------------------------------------------------------------

function jsAttribute(js) {

    return esc(js);
}


// =====================================================================
// SELECTOR-HILFEN
// =====================================================================

function selectorIds(
    selector,
    regex = null
) {

    const result = [];

    try {

        $(selector).each(
            id => {

                if (
                    !regex ||
                    regex.test(id)
                ) {

                    result.push(id);
                }
            }
        );

    } catch (e) {

        log(
            `[MB-Secure Dashboard] Selectorfehler "${selector}": ${e.message}`,
            'warn'
        );
    }

    return [
        ...new Set(result)
    ];
}


// ---------------------------------------------------------------------

function uidFrom(
    id,
    branch,
    field
) {

    const regex =
        new RegExp(
            '^' +
            ROOT.replace(/\./g, '\\.') +
            '\\.' +
            branch +
            '\\.(\\d+)\\.' +
            field.replace(/\./g, '\\.') +
            '$'
        );

    const match =
        regex.exec(id);

    return match
        ? match[1]
        : '';
}


// =====================================================================
// BEREICHE EINLESEN
// =====================================================================

async function collectPartitions() {

    const regex =
        new RegExp(
            '^' +
            ROOT.replace(/\./g, '\\.') +
            '\\.Partitions\\.(\\d+)\\.UID$'
        );


    const ids =
        selectorIds(
            `state[id=${ROOT}.Partitions.*.UID]`,
            regex
        );


    const result = [];


    for (const id of ids) {

        const uid =
            uidFrom(
                id,
                'Partitions',
                'UID'
            );


        if (!uid) {
            continue;
        }


        const base =
            `${ROOT}.Partitions.${uid}`;


        const alarm =
            truthy(
                await firstStateVal(
                    [
                        `${base}.AlarmClasses.AnyAlarm`,
                        `${base}.Alarm`
                    ],
                    false
                )
            );


        result.push({

            uid,

            name:
                await stateVal(
                    `${base}.Name`,
                    `Bereich ${uid}`
                ),

            number:
                Number(
                    await stateVal(
                        `${base}.Number`,
                        9999
                    )
                ),

            setState:
                String(
                    await stateVal(
                        `${base}.SetState`,
                        ''
                    )
                ),

            readyState:
                String(
                    await stateVal(
                        `${base}.ReadyState`,
                        ''
                    )
                ),

            alarm,

            fault:
                truthy(
                    await stateVal(
                        `${base}.Fault`,
                        false
                    )
                ),

            release:
                truthy(
                    await stateVal(
                        `${base}.Release`,
                        false
                    )
                ),

            releaseFullSet:
                truthy(
                    await stateVal(
                        `${base}.ReleaseFullSet`,
                        false
                    )
                ),

            releasePartSet:
                truthy(
                    await stateVal(
                        `${base}.ReleasePartSet`,
                        false
                    )
                ),

            faultFullSet:
                truthy(
                    await stateVal(
                        `${base}.FaultFullSet`,
                        false
                    )
                ),

            faultPartSet:
                truthy(
                    await stateVal(
                        `${base}.FaultPartSet`,
                        false
                    )
                ),


            // ---------------------------------------------------------
            // Experimentell bzw. API-seitig bestätigte Alarmklassen
            // bevorzugt aus unserer Derived-Struktur lesen.
            // ---------------------------------------------------------

            intruder:
                truthy(
                    await firstStateVal(
                        [
                            `${base}.AlarmClasses.Intruder`,
                            `${base}.atIntruder`
                        ],
                        false
                    )
                ),

            tamper:
                truthy(
                    await firstStateVal(
                        [
                            `${base}.AlarmClasses.Tamper`,
                            `${base}.atTamper`
                        ],
                        false
                    )
                ),

            fire:
                truthy(
                    await firstStateVal(
                        [
                            `${base}.AlarmClasses.Fire`,
                            `${base}.atFire`
                        ],
                        false
                    )
                ),

            fireSupervisory:
                truthy(
                    await firstStateVal(
                        [
                            `${base}.AlarmClasses.FireSupervisory`,
                            `${base}.atFireSupervisory`
                        ],
                        false
                    )
                ),

            panic:
                truthy(
                    await firstStateVal(
                        [
                            `${base}.AlarmClasses.Panic`,
                            `${base}.atPanic`
                        ],
                        false
                    )
                ),

            technical:
                truthy(
                    await firstStateVal(
                        [
                            `${base}.AlarmClasses.Technical`,
                            `${base}.atTechnical`
                        ],
                        false
                    )
                ),

            carbonMonoxide:
                truthy(
                    await firstStateVal(
                        [
                            `${base}.AlarmClasses.CarbonMonoxide`,
                            `${base}.atCarbonMonoxide`
                        ],
                        false
                    )
                )

        });
    }


    result.sort(
        (a, b) =>
            (
                a.number -
                b.number
            ) ||
            String(a.name)
                .localeCompare(
                    String(b.name),
                    'de'
                )
    );


    return result;
}


// =====================================================================
// MELDERGRUPPEN EINLESEN
// =====================================================================

async function collectGroups() {

    const regex =
        new RegExp(
            '^' +
            ROOT.replace(/\./g, '\\.') +
            '\\.DetectorGroups\\.(\\d+)\\.PartitionUID$'
        );


    const ids =
        selectorIds(
            `state[id=${ROOT}.DetectorGroups.*.PartitionUID]`,
            regex
        );


    const result = [];


    for (const id of ids) {

        const uid =
            uidFrom(
                id,
                'DetectorGroups',
                'PartitionUID'
            );


        if (!uid) {
            continue;
        }


        const base =
            `${ROOT}.DetectorGroups.${uid}`;


        const omitType =
            String(
                await stateVal(
                    `${base}.OmitType`,
                    'otNone'
                )
            );


        const internalBlocked =
            truthy(
                await firstStateVal(
                    [
                        `${base}.Semantics.InternalBlocked`
                    ],
                    omitType === 'otPartSet' ||
                    omitType === 'otAlwaysPartSet'
                )
            );


        const externalBlocked =
            truthy(
                await firstStateVal(
                    [
                        `${base}.Semantics.ExternalBlocked`
                    ],
                    omitType === 'otAlways' ||
                    omitType === 'otAlwaysPartSet'
                )
            );


        result.push({

            uid,

            partitionUID:
                String(
                    await stateVal(
                        `${base}.PartitionUID`,
                        ''
                    )
                ),

            name:
                await stateVal(
                    `${base}.Name`,
                    `Meldergruppe ${uid}`
                ),

            number:
                Number(
                    await stateVal(
                        `${base}.Number`,
                        9999
                    )
                ),

            omitType,

            internalBlocked,

            externalBlocked,

            bypass:
                truthy(
                    await firstStateVal(
                        [
                            `${base}.Semantics.Bypassed`,
                            `${base}.Bypass`
                        ],
                        false
                    )
                ),

            release:
                truthy(
                    await firstStateVal(
                        [
                            `${base}.Semantics.Released`,
                            `${base}.Release`
                        ],
                        false
                    )
                ),

            alarm:
                truthy(
                    await firstStateVal(
                        [
                            `${base}.Semantics.Alarm`,
                            `${base}.Alarm`
                        ],
                        false
                    )
                ),

            fault:
                truthy(
                    await firstStateVal(
                        [
                            `${base}.Semantics.Fault`,
                            `${base}.Fault`
                        ],
                        false
                    )
                ),

            memberCount:
                Number(
                    await stateVal(
                        `${base}.MemberCount`,
                        0
                    )
                ) || 0

        });
    }


    result.sort(
        (a, b) =>
            (
                a.number -
                b.number
            ) ||
            String(a.name)
                .localeCompare(
                    String(b.name),
                    'de'
                )
    );


    return result;
}


// =====================================================================
// AUSGÄNGE ZÄHLEN
// =====================================================================

async function getOutputCount() {

    const regex =
        new RegExp(
            '^' +
            ROOT.replace(/\./g, '\\.') +
            '\\.Outputs\\.(\\d+)\\.UID$'
        );


    const ids =
        selectorIds(
            `state[id=${ROOT}.Outputs.*.UID]`,
            regex
        );


    if (ids.length > 0) {
        return ids.length;
    }


    return Number(
        await stateVal(
            `${ROOT}.System.OutputCount`,
            0
        )
    ) || 0;
}


// =====================================================================
// STATUSAUSWERTUNG
// =====================================================================

function partitionStateInfo(p) {

    if (p.alarm) {

        return {
            text: 'ALARM',
            cls: 'danger',
            icon: '!'
        };
    }


    if (
        p.setState ===
        'pssFullSet'
    ) {

        return {
            text: 'Extern scharf',
            cls: 'danger',
            icon: '◆'
        };
    }


    if (
        p.setState ===
        'pssPartSet'
    ) {

        return {
            text: 'Intern scharf',
            cls: 'primary',
            icon: '⌂'
        };
    }


    return {
        text: 'Unscharf',
        cls: 'ok',
        icon: '○'
    };
}


// ---------------------------------------------------------------------

function overallInfo(partitions) {

    if (!partitions.length) {

        return {
            text: 'Keine Daten',
            cls: 'warn',
            sub: 'Noch keine Bereiche erkannt'
        };
    }


    if (
        partitions.some(
            p => p.alarm
        )
    ) {

        return {
            text: 'ALARM',
            cls: 'danger',
            sub: 'Mindestens ein Bereich im Alarm'
        };
    }


    const full =
        partitions.filter(
            p =>
                p.setState ===
                'pssFullSet'
        ).length;


    const part =
        partitions.filter(
            p =>
                p.setState ===
                'pssPartSet'
        ).length;


    const unset =
        partitions.filter(
            p =>
                p.setState ===
                'pssUnset'
        ).length;


    if (
        full ===
        partitions.length
    ) {

        return {
            text: 'Extern scharf',
            cls: 'danger',
            sub: 'Alle Bereiche extern scharf'
        };
    }


    if (
        part ===
        partitions.length
    ) {

        return {
            text: 'Intern scharf',
            cls: 'primary',
            sub: 'Alle Bereiche intern scharf'
        };
    }


    if (
        unset ===
        partitions.length
    ) {

        return {
            text: 'Unscharf',
            cls: 'ok',
            sub: 'Alle Bereiche unscharf'
        };
    }


    return {
        text: 'Gemischt',
        cls: 'warn',

        sub:
            `${full} extern · ` +
            `${part} intern · ` +
            `${unset} unscharf`
    };
}


// ---------------------------------------------------------------------

function alarmLabels(p) {

    const result = [];


    if (p.intruder) {
        result.push('Einbruch');
    }


    if (p.tamper) {
        result.push('Sabotage');
    }


    if (p.fire) {
        result.push('Brand');
    }


    if (p.fireSupervisory) {
        result.push('Brand-Überwachung');
    }


    if (p.panic) {
        result.push('Überfall/Panik');
    }


    if (p.technical) {
        result.push('Technisch');
    }


    if (p.carbonMonoxide) {
        result.push('CO');
    }


    return result;
}


// =====================================================================
// INLINE VIS2 BEDIENUNG
// =====================================================================

// ---------------------------------------------------------------------
// Direkter Write-Enable-Schalter.
// KEINE Hilfsfunktion im Browser nötig.
// ---------------------------------------------------------------------

function writeEnableJs(value) {

    return jsAttribute(

        `vis.setValue(` +
        `${jsString(WRITE_ENABLED)},` +
        `${value ? 'true' : 'false'}` +
        `);return false;`

    );
}


// ---------------------------------------------------------------------
// Dashboard-Aktion direkt in den Dashboard.Action-Datenpunkt schreiben.
// Das Backend validiert Command und UID erneut.
// ---------------------------------------------------------------------

function actionJs(
    command,
    uid,
    confirmText = ''
) {

    let js = '';


    if (confirmText) {

        js +=
            `if(!confirm(${jsString(confirmText)})){` +
            `return false;` +
            `}`;
    }


    js +=
        `vis.setValue(` +
        `${jsString(DP_ACTION)},` +
        `Date.now()+${jsString(`|${command}|${uid}`)}` +
        `);` +
        `return false;`;


    return jsAttribute(js);
}


// ---------------------------------------------------------------------
// Suchfeld ebenfalls ohne selbst definierte Browserfunktion.
// ---------------------------------------------------------------------

function searchJs() {

    const js =
        `var q=String(this.value||'').toLowerCase().trim();` +

        `document.querySelectorAll('.mb-root .mb-group')` +
        `.forEach(function(el){` +

        `var s=String(el.getAttribute('data-search')||'');` +

        `el.classList.toggle('mb-hidden',!!q&&s.indexOf(q)<0);` +

        `});`;


    return jsAttribute(js);
}


// =====================================================================
// BUTTONS
// =====================================================================

function button(
    label,
    command,
    uid,
    css,
    confirmText = '',
    disabled = false
) {

    return `
        <button
            type="button"
            class="mb-btn ${css}${disabled ? ' disabled' : ''}"
            ${disabled ? 'disabled' : ''}
            ${
                disabled
                    ? ''
                    : `onclick="${actionJs(
                        command,
                        uid,
                        confirmText
                    )}"`
            }
        >
            ${esc(label)}
        </button>
    `;
}


// ---------------------------------------------------------------------

function groupToggle(
    label,
    active,
    command,
    uid,
    disabled = false,
    css = ''
) {

    return `
        <button
            type="button"
            class="mb-switch-row${active ? ' active' : ''}${disabled ? ' disabled' : ''}"
            ${disabled ? 'disabled' : ''}
            ${
                disabled
                    ? ''
                    : `onclick="${actionJs(
                        command,
                        uid
                    )}"`
            }
        >

            <span class="mb-switch-label">
                ${esc(label)}
            </span>

            <span class="mb-toggle ${css}">
                <i></i>
            </span>

        </button>
    `;
}


// =====================================================================
// MELDERGRUPPENSTATUS
// =====================================================================

function groupStatus(g) {

    if (g.alarm) {

        return {
            text: 'Alarm',
            cls: 'danger'
        };
    }


    if (g.fault) {

        return {
            text: 'Störung',
            cls: 'warn'
        };
    }


    if (g.bypass) {

        return {
            text: 'Übergegangen',
            cls: 'primary'
        };
    }


    if (g.internalBlocked && g.externalBlocked) {

        return {
            text: 'Intern + extern gesperrt',
            cls: 'warn'
        };
    }


    if (g.externalBlocked) {

        return {
            text: 'Extern gesperrt',
            cls: 'warn'
        };
    }


    if (g.internalBlocked) {

        return {
            text: 'Intern gesperrt',
            cls: 'warn'
        };
    }


    if (g.release) {

        return {
            text: 'Ausgelöst',
            cls: 'warn'
        };
    }


    return {
        text: 'Normal',
        cls: 'ok'
    };
}


// =====================================================================
// MELDERGRUPPENKARTE
// =====================================================================

function renderGroupCard(
    g,
    partition
) {

    const status =
        groupStatus(g);


    const internal =
        g.internalBlocked;


    const external =
        g.externalBlocked;


    const knownOmitTypes =
        new Set([
            'otNone',
            'otPartSet',
            'otAlways',
            'otAlwaysPartSet'
        ]);


    const unknownOmit =
        g.omitType &&
        !knownOmitTypes.has(g.omitType);


    // ---------------------------------------------------------------
    // Bypass:
    // - Bereich muss unscharf sein
    // - Gruppe darf nicht im Alarm sein
    // - für Bypass ON muss Release/Fault vorhanden sein
    // - vorhandener Bypass darf immer wieder ausgeschaltet werden
    // ---------------------------------------------------------------

    const bypassAllowed =
        (
            g.bypass
        ) ||
        (
            !g.alarm &&
            partition.setState === 'pssUnset' &&
            (
                g.release ||
                g.fault
            )
        );


    const internalCommand =
        internal
            ? 'GROUP_UNOMIT_PART'
            : 'GROUP_OMIT_PART';


    const externalCommand =
        external
            ? 'GROUP_UNOMIT_ALWAYS'
            : 'GROUP_OMIT_ALWAYS';


    const bypassCommand =
        g.bypass
            ? 'GROUP_BYPASS_OFF'
            : 'GROUP_BYPASS_ON';


    return `
        <article
            class="mb-group"
            data-search="${esc(
                (
                    g.name +
                    ' ' +
                    g.uid
                ).toLowerCase()
            )}"
        >

            <div class="mb-group-head">

                <div class="mb-group-icon">
                    ◫
                </div>


                <div class="mb-group-title">

                    <b>
                        ${esc(g.name)}
                    </b>

                    <small>
                        UID ${esc(g.uid)}
                        ·
                        ${g.memberCount} Melder
                    </small>

                </div>


                <span class="mb-chip ${status.cls}">
                    ${esc(status.text)}
                </span>

            </div>


            <div class="mb-group-flags">

                ${
                    g.release
                        ? '<span>● ausgelöst</span>'
                        : ''
                }

                ${
                    g.fault
                        ? '<span>⚠ Störung</span>'
                        : ''
                }

                ${
                    g.alarm
                        ? '<span>⛔ Alarm</span>'
                        : ''
                }

            </div>


            <div class="mb-switches">

                ${
                    groupToggle(
                        'Intern sperren',
                        internal,
                        internalCommand,
                        g.uid,
                        unknownOmit,
                        internal
                            ? 'on-blue'
                            : ''
                    )
                }


                ${
                    groupToggle(
                        'Extern sperren',
                        external,
                        externalCommand,
                        g.uid,
                        unknownOmit,
                        external
                            ? 'on-red'
                            : ''
                    )
                }


                ${
                    groupToggle(
                        'Einmalig übergehen',
                        g.bypass,
                        bypassCommand,
                        g.uid,
                        !bypassAllowed,
                        g.bypass
                            ? 'on-violet'
                            : ''
                    )
                }

            </div>

        </article>
    `;
}


// =====================================================================
// BEREICHSKARTE
// =====================================================================

function renderPartition(
    p,
    groups
) {

    const state =
        partitionStateInfo(p);


    const alarms =
        alarmLabels(p);


    const alarmGroups =
        groups.filter(
            g => g.alarm
        ).length;


    const internalBlocked =
        groups.filter(
            g => g.internalBlocked
        ).length;


    const externalBlocked =
        groups.filter(
            g => g.externalBlocked
        ).length;


    const bypassed =
        groups.filter(
            g => g.bypass
        ).length;


    const partBlocked =
        p.releasePartSet ||
        p.faultPartSet;


    const fullBlocked =
        p.releaseFullSet ||
        p.faultFullSet;


    const isUnset =
        p.setState ===
        'pssUnset';


    const isPart =
        p.setState ===
        'pssPartSet';


    const isFull =
        p.setState ===
        'pssFullSet';


    return `
        <details
            class="mb-area"
            open
        >

            <summary>

                <div class="mb-area-icon ${state.cls}">
                    ${state.icon}
                </div>


                <div class="mb-area-title">

                    <b>
                        ${esc(p.name)}
                    </b>

                    <small>
                        UID ${esc(p.uid)}
                        ·
                        ${groups.length} Meldergruppen
                    </small>

                </div>


                <div class="mb-area-meta">

                    ${
                        alarms.length
                            ?
                            `
                            <span class="mb-chip danger">
                                ${esc(
                                    alarms.join(' · ')
                                )}
                            </span>
                            `
                            :
                            ''
                    }


                    ${
                        partBlocked &&
                        !isPart
                            ?
                            `
                            <span class="mb-chip warn">
                                Intern nicht bereit
                            </span>
                            `
                            :
                            ''
                    }


                    ${
                        fullBlocked &&
                        !isFull
                            ?
                            `
                            <span class="mb-chip warn">
                                Extern nicht bereit
                            </span>
                            `
                            :
                            ''
                    }


                    <span class="mb-chip ${state.cls}">
                        ${esc(state.text)}
                    </span>

                </div>

            </summary>


            <div class="mb-area-body">


                <div class="mb-area-actions">

                    ${
                        button(
                            'Unscharf',
                            'PARTITION_UNSET',
                            p.uid,
                            'neutral',
                            `${p.name}: unscharf schalten?`,
                            isUnset
                        )
                    }


                    ${
                        button(
                            'Intern scharf',
                            'PARTITION_PARTSET',
                            p.uid,
                            'primary',
                            `${p.name}: intern scharf schalten?`,
                            isPart ||
                            partBlocked
                        )
                    }


                    ${
                        button(
                            'Extern scharf',
                            'PARTITION_FULLSET',
                            p.uid,
                            'danger',
                            `${p.name}: EXTERN scharf schalten?`,
                            isFull ||
                            fullBlocked
                        )
                    }


                    ${
                        button(
                            'Löschen',
                            'PARTITION_CLEAR',
                            p.uid,
                            'secondary',
                            `${p.name}: Bereich löschen / Supervisor Clear ausführen?`,
                            !isUnset
                        )
                    }

                </div>


                <div class="mb-area-stats">

                    <div>
                        <span>Meldergruppen</span>
                        <b>${groups.length}</b>
                    </div>


                    <div>

                        <span>Im Alarm</span>

                        <b class="${alarmGroups ? 'txt-danger' : ''}">
                            ${alarmGroups}
                        </b>

                    </div>


                    <div>
                        <span>Intern gesperrt</span>
                        <b>${internalBlocked}</b>
                    </div>


                    <div>
                        <span>Extern gesperrt</span>
                        <b>${externalBlocked}</b>
                    </div>


                    <div>
                        <span>Übergegangen</span>
                        <b>${bypassed}</b>
                    </div>

                </div>


                <div class="mb-groups">

                    ${
                        groups
                            .map(
                                g =>
                                    renderGroupCard(
                                        g,
                                        p
                                    )
                            )
                            .join('')
                    }

                </div>

            </div>

        </details>
    `;
}


// =====================================================================
// DASHBOARD RENDERN
// =====================================================================

async function renderDashboard() {

    const [
        partitions,
        groups,
        outputCount
    ] =
        await Promise.all([

            collectPartitions(),

            collectGroups(),

            getOutputCount()

        ]);


    const connected =
        truthy(
            await stateVal(
                `${ROOT}.System.Connected`,
                false
            )
        );


    const panelVersion =
        await firstStateVal(
            [
                `${ROOT}.Info.PanelVersion`,
                `${ROOT}.Info.Version`
            ],
            '–'
        );


    const lastFullSync =
        await stateVal(
            `${ROOT}.System.LastFullSync`,
            '–'
        );


    const changeCounter =
        await stateVal(
            `${ROOT}.System.ChangeCounter`,
            '–'
        );


    const writeEnabled =
        truthy(
            await stateVal(
                WRITE_ENABLED,
                false
            )
        );


    const busy =
        truthy(
            await stateVal(
                WRITE_BUSY,
                false
            )
        );


    const lastVerified =
        truthy(
            await stateVal(
                WRITE_VERIFIED,
                false
            )
        );


    const lastVerification =
        String(
            await stateVal(
                WRITE_VERIFICATION,
                ''
            )
        );


    const lastWriteError =
        String(
            await stateVal(
                WRITE_ERROR,
                ''
            )
        );


    const actionResult =
        String(
            await stateVal(
                DP_ACTION_RESULT,
                ''
            )
        );


    const overall =
        overallInfo(partitions);


    const alarmCount =
        partitions.filter(
            p => p.alarm
        ).length;


    const groupAlarmCount =
        groups.filter(
            g => g.alarm
        ).length;


    const blockedCount =
        groups.filter(
            g =>
                g.internalBlocked ||
                g.externalBlocked
        ).length;


    // -----------------------------------------------------------------
    // Gruppen den Bereichen zuordnen
    // -----------------------------------------------------------------

    const byPartition =
        new Map();


    partitions.forEach(
        p => {

            byPartition.set(
                p.uid,
                []
            );
        }
    );


    groups.forEach(
        g => {

            if (
                !byPartition.has(
                    g.partitionUID
                )
            ) {

                byPartition.set(
                    g.partitionUID,
                    []
                );
            }


            byPartition
                .get(
                    g.partitionUID
                )
                .push(g);
        }
    );


    // =================================================================
    // HTML
    // =================================================================

    const html = `

<style>

.mb-root,
.mb-root *,
.mb-root *::before,
.mb-root *::after {
    box-sizing:border-box;
}


.mb-root {

    --line:#26384a;

    --text:#edf5ff;

    --muted:#8fa3b8;

    --green:#20d98b;

    --blue:#3182ff;

    --red:#ff4d62;

    --amber:#f2b84b;

    --violet:#9a6cff;


    width:100%;

    max-width:100%;

    min-width:0;

    min-height:100%;

    margin:0;

    padding:
        clamp(
            6px,
            1vw,
            14px
        );


    overflow-x:hidden;

    overflow-x:clip;

    overflow-y:visible;


    background:
        linear-gradient(
            135deg,
            #09111a,
            #0d1722 48%,
            #081018
        );


    color:var(--text);


    font-family:
        Inter,
        Roboto,
        Arial,
        sans-serif;


    font-size:14px;


    overflow-wrap:anywhere;


    container-type:inline-size;
}


.mb-root button,
.mb-root input {

    font:inherit;
}


.mb-root button {

    touch-action:manipulation;
}


.mb-shell,
.mb-areas,
.mb-area,
.mb-area-body,
.mb-groups,
.mb-summary,
.mb-toolbar,
.mb-status {

    width:100%;

    max-width:100%;

    min-width:0;
}


.mb-shell {

    margin:0;

    padding:0;

    overflow-x:hidden;

    overflow-x:clip;
}


/* ===============================================================
   KOPFBEREICH
   =============================================================== */

.mb-top {

    width:100%;

    min-width:0;

    display:flex;

    flex-wrap:wrap;

    justify-content:space-between;

    align-items:center;

    gap:10px;

    padding:
        8px 2px 14px;
}


.mb-brand {

    display:flex;

    align-items:center;

    gap:10px;

    min-width:0;

    flex:
        1 1 260px;
}


.mb-logo {

    flex:
        0 0 48px;

    width:48px;

    height:48px;

    border-radius:14px;


    background:
        linear-gradient(
            145deg,
            #b8d4ff,
            #5f87bf
        );


    color:#09203a;


    display:flex;

    align-items:center;

    justify-content:center;


    font-size:25px;

    font-weight:900;


    box-shadow:
        0 10px 30px #0006;
}


.mb-title {

    min-width:0;

    flex:
        1 1 auto;
}


.mb-title h1 {

    margin:0;

    font-size:
        clamp(
            21px,
            3cqw,
            29px
        );

    line-height:1.15;
}


.mb-title p {

    margin:
        4px 0 0;

    color:var(--muted);

    line-height:1.3;
}


.mb-top-right {

    display:flex;

    flex-wrap:wrap;

    align-items:center;

    justify-content:flex-end;

    gap:7px;

    min-width:0;

    max-width:100%;
}


/* ===============================================================
   PILLS
   =============================================================== */

.mb-pill {

    min-width:0;

    max-width:100%;

    display:inline-flex;

    align-items:center;

    justify-content:center;

    gap:7px;


    padding:
        8px 10px;


    border:
        1px solid var(--line);


    background:#12202e;


    border-radius:999px;


    color:var(--muted);


    white-space:normal;

    text-align:center;
}


.mb-dot {

    flex:
        0 0 9px;

    width:9px;

    height:9px;

    border-radius:50%;

    background:#6c7885;
}


.mb-dot.on {

    background:var(--green);

    box-shadow:
        0 0 14px #20d98b99;
}


.mb-enable {

    appearance:none;

    cursor:pointer;

    color:#fff;
}


.mb-enable.on {

    border-color:#247a59;

    background:#12392d;
}


.mb-enable.off {

    border-color:#72414a;

    background:#321920;
}


/* ===============================================================
   STATUSKARTEN
   =============================================================== */

.mb-summary {

    display:grid;


    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                min(
                    100%,
                    190px
                ),
                1fr
            )
        );


    gap:8px;

    margin-bottom:11px;
}


.mb-card {

    min-width:0;

    min-height:86px;


    border:
        1px solid var(--line);


    border-radius:13px;


    background:
        linear-gradient(
            145deg,
            #142334,
            #101b28
        );


    padding:11px;


    display:flex;

    gap:9px;

    align-items:center;


    overflow:hidden;


    box-shadow:
        0 8px 30px #0003;
}


.mb-card > div:last-child {

    min-width:0;

    flex:
        1 1 auto;
}


.mb-card-icon {

    flex:
        0 0 40px;

    width:40px;

    height:40px;

    border-radius:11px;


    display:flex;

    align-items:center;

    justify-content:center;


    font-size:20px;


    background:#203449;
}


.mb-card.ok .mb-card-icon {

    background:#0d4a37;

    color:var(--green);
}


.mb-card.primary .mb-card-icon {

    background:#173e7d;

    color:#7db0ff;
}


.mb-card.warn .mb-card-icon {

    background:#4d3b15;

    color:#ffd36f;
}


.mb-card.danger .mb-card-icon {

    background:#5a1f29;

    color:#ff8190;
}


.mb-card small {

    display:block;

    color:var(--muted);

    font-size:10px;

    line-height:1.25;
}


.mb-card b {

    display:block;

    margin:
        2px 0;

    font-size:
        clamp(
            16px,
            2.2cqw,
            21px
        );

    line-height:1.15;
}


/* ===============================================================
   TOOLBAR
   =============================================================== */

.mb-toolbar {

    display:flex;

    flex-wrap:wrap;

    align-items:center;

    gap:8px;


    margin:
        8px 0 11px;
}


.mb-search {

    flex:
        1 1 240px;


    width:auto;

    max-width:100%;

    min-width:0;


    background:#12202e;


    border:
        1px solid var(--line);


    border-radius:10px;


    color:#fff;


    padding:
        10px 12px;


    outline:none;
}


.mb-search:focus {

    border-color:#3b78b8;
}


/* ===============================================================
   BEREICHE
   =============================================================== */

.mb-area {

    border:
        1px solid var(--line);


    border-radius:13px;


    background:#0e1823;


    margin:
        9px 0;


    overflow:hidden;


    box-shadow:
        0 8px 24px #0003;
}


.mb-area > summary {

    list-style:none;

    cursor:pointer;


    width:100%;

    min-width:0;


    display:flex;

    flex-wrap:wrap;

    align-items:center;


    gap:9px;


    padding:
        10px 11px;


    background:
        linear-gradient(
            90deg,
            #142333,
            #101c28
        );


    border-bottom:
        1px solid transparent;
}


.mb-area[open] > summary {

    border-bottom-color:
        var(--line);
}


.mb-area > summary::-webkit-details-marker {

    display:none;
}


.mb-area-icon {

    flex:
        0 0 42px;


    width:42px;

    height:42px;


    border-radius:11px;


    display:flex;

    align-items:center;

    justify-content:center;


    font-size:22px;

    font-weight:900;
}


.mb-area-icon.ok {

    background:#0d4a37;

    color:var(--green);
}


.mb-area-icon.primary {

    background:#173e7d;

    color:#7db0ff;
}


.mb-area-icon.warn {

    background:#4d3b15;

    color:#ffd36f;
}


.mb-area-icon.danger {

    background:#5a1f29;

    color:#ff8190;
}


.mb-area-title {

    min-width:0;

    flex:
        1 1 190px;
}


.mb-area-title b {

    display:block;

    font-size:
        clamp(
            16px,
            2.1cqw,
            20px
        );

    line-height:1.2;
}


.mb-area-title small {

    display:block;

    margin-top:3px;

    color:var(--muted);
}


.mb-area-meta {

    min-width:0;

    max-width:100%;


    display:flex;

    align-items:center;

    justify-content:flex-end;

    flex-wrap:wrap;


    gap:6px;


    flex:
        0 1 auto;
}


/* ===============================================================
   CHIPS
   =============================================================== */

.mb-chip {

    min-width:0;

    max-width:100%;


    display:inline-flex;

    align-items:center;

    justify-content:center;


    padding:
        5px 8px;


    border-radius:999px;


    font-size:11px;

    line-height:1.2;

    font-weight:700;


    background:#263646;

    color:#cbd9e6;


    text-align:center;

    white-space:normal;
}


.mb-chip.ok {

    background:#0d4a37;

    color:#49efa8;
}


.mb-chip.primary {

    background:#173e7d;

    color:#85b5ff;
}


.mb-chip.warn {

    background:#4d3b15;

    color:#ffd36f;
}


.mb-chip.danger {

    background:#5a1f29;

    color:#ff8190;
}


.mb-area-body {

    padding:9px;
}


/* ===============================================================
   BEREICHSBUTTONS
   =============================================================== */

.mb-area-actions {

    width:100%;


    display:grid;


    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                min(
                    100%,
                    145px
                ),
                1fr
            )
        );


    gap:7px;
}


.mb-btn {

    appearance:none;


    width:100%;

    max-width:100%;

    min-width:0;


    min-height:44px;


    border:
        1px solid transparent;


    border-radius:9px;


    padding:
        9px 8px;


    color:#fff;


    font-weight:800;

    line-height:1.2;


    text-align:center;

    white-space:normal;


    cursor:pointer;


    transition:
        .15s transform,
        .15s filter;
}


.mb-btn:hover:not(:disabled) {

    filter:
        brightness(1.12);


    transform:
        translateY(-1px);
}


.mb-btn:disabled,
.mb-btn.disabled {

    opacity:.38;

    cursor:not-allowed;

    transform:none;
}


.mb-btn.neutral {

    background:#28425d;

    border-color:#3d5f80;
}


.mb-btn.primary {

    background:#1765d1;

    border-color:#3483ee;
}


.mb-btn.danger {

    background:#b92b3d;

    border-color:#e04659;
}


.mb-btn.secondary {

    background:#34475b;

    border-color:#526b83;
}


/* ===============================================================
   BEREICHSSTATISTIK
   =============================================================== */

.mb-area-stats {

    display:grid;


    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                min(
                    100%,
                    105px
                ),
                1fr
            )
        );


    gap:1px;


    border:
        1px solid var(--line);


    background:var(--line);


    border-radius:9px;


    overflow:hidden;


    margin:
        8px 0;
}


.mb-area-stats > div {

    min-width:0;

    background:#121f2c;

    padding:8px;
}


.mb-area-stats span {

    display:block;

    color:var(--muted);

    font-size:9px;

    line-height:1.2;
}


.mb-area-stats b {

    display:block;

    margin-top:2px;

    font-size:16px;
}


.txt-danger {

    color:var(--red);
}


/* ===============================================================
   MELDERGRUPPEN
   =============================================================== */

.mb-groups {

    display:grid;


    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                min(
                    100%,
                    285px
                ),
                1fr
            )
        );


    gap:8px;


    align-items:stretch;
}


.mb-group {

    width:100%;

    max-width:100%;

    min-width:0;


    border:
        1px solid var(--line);


    background:
        linear-gradient(
            145deg,
            #142230,
            #0e1821
        );


    border-radius:10px;


    padding:9px;


    overflow:hidden;
}


.mb-group-head {

    width:100%;

    min-width:0;


    display:flex;

    flex-wrap:wrap;


    gap:7px;


    align-items:center;
}


.mb-group-icon {

    flex:
        0 0 31px;


    width:31px;

    height:31px;


    border-radius:8px;


    background:#1b3043;


    display:flex;

    align-items:center;

    justify-content:center;


    font-size:18px;
}


.mb-group-title {

    min-width:0;

    flex:
        1 1 150px;
}


.mb-group-title b {

    display:block;

    line-height:1.2;
}


.mb-group-title small {

    display:block;

    margin-top:2px;

    color:var(--muted);

    font-size:9px;

    line-height:1.2;
}


.mb-group-head > .mb-chip {

    margin-left:auto;

    flex:
        0 1 auto;
}


.mb-group-flags {

    width:100%;

    min-width:0;

    min-height:18px;


    padding:
        5px 0;


    display:flex;

    flex-wrap:wrap;


    gap:
        4px 8px;


    font-size:9px;

    color:#f5bd63;
}


/* ===============================================================
   SWITCHES
   =============================================================== */

.mb-switches {

    width:100%;

    display:grid;

    gap:2px;
}


.mb-switch-row {

    appearance:none;


    width:100%;

    max-width:100%;

    min-width:0;


    min-height:42px;


    border:0;


    background:transparent;


    color:#dce8f3;


    display:flex;


    justify-content:space-between;

    align-items:center;


    gap:9px;


    padding:
        5px 2px;


    cursor:pointer;


    text-align:left;
}


.mb-switch-row.disabled {

    opacity:.35;

    cursor:not-allowed;
}


.mb-switch-label {

    min-width:0;

    flex:
        1 1 auto;
}


.mb-toggle {

    flex:
        0 0 38px;


    width:38px;

    height:22px;


    border-radius:999px;


    background:#53677a;


    position:relative;


    transition:.15s;
}


.mb-toggle i {

    position:absolute;


    left:3px;

    top:3px;


    width:16px;

    height:16px;


    border-radius:50%;


    background:#eef5fb;


    transition:.15s;
}


.mb-switch-row.active .mb-toggle {

    background:#2374df;
}


.mb-switch-row.active .mb-toggle.on-red {

    background:#d2384b;
}


.mb-switch-row.active .mb-toggle.on-violet {

    background:#8052df;
}


.mb-switch-row.active .mb-toggle i {

    left:19px;
}


/* ===============================================================
   SYSTEMSTATUS
   =============================================================== */

.mb-status {

    margin-top:10px;


    border:
        1px solid var(--line);


    border-radius:11px;


    background:#101c27;


    padding:
        8px 9px;


    display:grid;


    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                min(
                    100%,
                    180px
                ),
                1fr
            )
        );


    gap:7px;


    color:var(--muted);


    font-size:10px;
}


.mb-status > div {

    min-width:0;
}


.mb-status b {

    color:#dce8f3;
}


.mb-empty {

    width:100%;


    padding:18px;


    text-align:center;


    color:var(--muted);


    border:
        1px dashed var(--line);


    border-radius:10px;
}


.mb-hidden {

    display:none !important;
}

</style>


<div class="mb-root">

<div class="mb-shell">


    <header class="mb-top">


        <div class="mb-brand">

            <div class="mb-logo">
                ⬟
            </div>


            <div class="mb-title">

                <h1>
                    MB-Secure
                </h1>

                <p>
                    Anlagenübersicht · Bedienpanel
                </p>

            </div>

        </div>


        <div class="mb-top-right">


            <span class="mb-pill">

                <i class="mb-dot ${connected ? 'on' : ''}">
                </i>

                ${
                    connected
                        ? 'Zentrale verbunden'
                        : 'Offline'
                }

            </span>


            <button
                type="button"
                class="mb-pill mb-enable ${writeEnabled ? 'on' : 'off'}"
                onclick="${writeEnableJs(!writeEnabled)}"
            >

                ${
                    writeEnabled
                        ? '🔓 Bedienung freigegeben'
                        : '🔒 Bedienung gesperrt'
                }

            </button>


            ${
                busy
                    ?
                    `
                    <span class="mb-pill">
                        ⏳ Befehl läuft
                    </span>
                    `
                    :
                    ''
            }

        </div>

    </header>


    <section class="mb-summary">


        <div class="mb-card ${overall.cls}">

            <div class="mb-card-icon">
                ⬟
            </div>


            <div>

                <small>
                    Anlage gesamt
                </small>

                <b>
                    ${esc(overall.text)}
                </b>

                <small>
                    ${esc(overall.sub)}
                </small>

            </div>

        </div>


        <div class="mb-card primary">

            <div class="mb-card-icon">
                ⌂
            </div>


            <div>

                <small>
                    Bereiche
                </small>

                <b>
                    ${partitions.length}
                </b>

                <small>

                    ${
                        partitions.filter(
                            p =>
                                p.setState ===
                                'pssUnset'
                        ).length
                    }
                    unscharf ·

                    ${
                        partitions.filter(
                            p =>
                                p.setState ===
                                'pssPartSet'
                        ).length
                    }
                    intern ·

                    ${
                        partitions.filter(
                            p =>
                                p.setState ===
                                'pssFullSet'
                        ).length
                    }
                    extern

                </small>

            </div>

        </div>


        <div class="mb-card">

            <div class="mb-card-icon">
                ◫
            </div>


            <div>

                <small>
                    Meldergruppen
                </small>

                <b>
                    ${groups.length}
                </b>

                <small>
                    ${blockedCount} gesperrt
                </small>

            </div>

        </div>


        <div class="mb-card warn">

            <div class="mb-card-icon">
                ●
            </div>


            <div>

                <small>
                    Ausgänge
                </small>

                <b>
                    ${outputCount}
                </b>

                <small>
                    erkannt
                </small>

            </div>

        </div>


        <div class="mb-card ${alarmCount || groupAlarmCount ? 'danger' : 'ok'}">

            <div class="mb-card-icon">
                !
            </div>


            <div>

                <small>
                    Bereiche im Alarm
                </small>

                <b>
                    ${alarmCount}
                </b>

                <small>

                    ${
                        groupAlarmCount
                            ?
                            `${groupAlarmCount} Meldergruppen im Alarm`
                            :
                            'Alles in Ordnung'
                    }

                </small>

            </div>

        </div>

    </section>


    <div class="mb-toolbar">

        <input
            class="mb-search"
            type="search"
            placeholder="Meldergruppe suchen…"
            oninput="${searchJs()}"
        >


        <span class="mb-pill">

            ${partitions.length}
            Bereiche ·
            ${groups.length}
            Gruppen

        </span>

    </div>


    <main class="mb-areas">

        ${
            partitions.length
                ?
                partitions
                    .map(
                        p =>
                            renderPartition(
                                p,
                                byPartition.get(p.uid) || []
                            )
                    )
                    .join('')
                :
                `
                <div class="mb-empty">
                    Noch keine Bereichsdaten vorhanden.
                </div>
                `
        }

    </main>


    <footer class="mb-status">


        <div>

            Dashboard

            <br>

            <b>
                v${VERSION}
            </b>

        </div>


        <div>

            Zentrale

            <br>

            <b>
                ${esc(panelVersion)}
            </b>

        </div>


        <div>

            ChangeCounter

            <br>

            <b>
                ${esc(changeCounter)}
            </b>

        </div>


        <div>

            Letzter FullSync

            <br>

            <b>
                ${esc(lastFullSync)}
            </b>

        </div>


        <div>

            Letzter Bedienstatus

            <br>

            <b>
                ${
                    esc(
                        lastWriteError ||
                        lastVerification ||
                        actionResult ||
                        (
                            lastVerified
                                ? 'Readback bestätigt'
                                : '–'
                        )
                    )
                }
            </b>

        </div>

    </footer>


</div>

</div>
`;


    await setStateAsync(
        DP_HTML,
        html,
        true
    );


    await setStateAsync(
        DP_LAST_RENDER,
        new Date()
            .toLocaleString(
                'de-DE'
            ),
        true
    );
}


// =====================================================================
// RENDER-DEBOUNCE
// =====================================================================

function scheduleRender() {

    if (renderTimer) {

        clearTimeout(
            renderTimer
        );
    }


    renderTimer =
        setTimeout(

            async () => {

                renderTimer =
                    null;


                try {

                    await renderDashboard();

                } catch (e) {

                    log(
                        `[MB-Secure Dashboard] Renderfehler: ${
                            e.stack ||
                            e.message ||
                            e
                        }`,
                        'error'
                    );
                }

            },

            250
        );
}


// =====================================================================
// ZIELPRÜFUNG
// =====================================================================

async function validateDashboardTarget(
    command,
    uid
) {

    if (
        command.startsWith(
            'PARTITION_'
        )
    ) {

        if (
            !existsState(
                `${ROOT}.Partitions.${uid}.UID`
            )
        ) {

            throw new Error(
                `Bereich UID ${uid} existiert im Mirror nicht.`
            );
        }

        return;
    }


    if (
        command.startsWith(
            'GROUP_'
        )
    ) {

        if (
            !existsState(
                `${ROOT}.DetectorGroups.${uid}.PartitionUID`
            )
        ) {

            throw new Error(
                `Meldergruppe UID ${uid} existiert im Mirror nicht.`
            );
        }

        return;
    }


    throw new Error(
        `Nicht unterstützte Befehlsart: ${command}`
    );
}


// =====================================================================
// WRITE-READBACK ABWARTEN
// =====================================================================

async function waitForWriteCompletion(
    oldLastTime,
    timeoutMs = 45000
) {

    const started =
        Date.now();


    let seenStart =
        false;


    while (
        Date.now() -
        started <
        timeoutMs
    ) {

        const busy =
            truthy(
                await stateVal(
                    WRITE_BUSY,
                    false
                )
            );


        const lastTime =
            String(
                await stateVal(
                    WRITE_LAST_TIME,
                    ''
                )
            );


        if (
            busy ||
            (
                lastTime &&
                lastTime !==
                String(
                    oldLastTime ||
                    ''
                )
            )
        ) {

            seenStart =
                true;
        }


        if (
            seenStart &&
            !busy
        ) {

            return true;
        }


        await new Promise(
            resolve =>
                setTimeout(
                    resolve,
                    150
                )
        );
    }


    return false;
}


// =====================================================================
// DASHBOARD-AKTION
// =====================================================================

async function handleAction(obj) {

    if (
        !obj ||
        !obj.state
    ) {

        return;
    }


    // -----------------------------------------------------------------
    // Dashboard-Bedienung muss von VIS mit ack=false kommen.
    // -----------------------------------------------------------------

    if (
        obj.state.ack === true
    ) {

        return;
    }


    if (actionRunning) {

        await setStateAsync(
            DP_ACTION_RESULT,
            'Abgelehnt: bereits ein Dashboard-Befehl in Bearbeitung.',
            true
        );

        return;
    }


    const raw =
        String(
            obj.state.val ||
            ''
        );


    const parts =
        raw.split('|');


    // erwartet:
    // timestamp|COMMAND|UID

    if (
        parts.length !== 3
    ) {

        await setStateAsync(
            DP_ACTION_RESULT,
            `Ungültiges Aktionsformat: ${raw}`,
            true
        );

        return;
    }


    const timestamp =
        String(
            parts[0] ||
            ''
        )
            .trim();


    const command =
        String(
            parts[1] ||
            ''
        )
            .trim()
            .toUpperCase();


    const uid =
        String(
            parts[2] ||
            ''
        )
            .trim();


    if (
        !/^\d+$/.test(timestamp)
    ) {

        await setStateAsync(
            DP_ACTION_RESULT,
            'Abgelehnt: ungültiger Aktionszeitstempel.',
            true
        );

        return;
    }


    if (
        !ALLOWED_COMMANDS.has(
            command
        ) ||
        !/^\d+$/.test(uid)
    ) {

        await setStateAsync(
            DP_ACTION_RESULT,
            `Abgelehnt: ${command} / UID ${uid}`,
            true
        );

        return;
    }


    actionRunning =
        true;


    try {

        // -------------------------------------------------------------
        // Ziel nochmals serverseitig validieren
        // -------------------------------------------------------------

        await validateDashboardTarget(
            command,
            uid
        );


        // -------------------------------------------------------------
        // Bedienfreigabe nochmals serverseitig prüfen
        // -------------------------------------------------------------

        const enabled =
            truthy(
                await stateVal(
                    WRITE_ENABLED,
                    false
                )
            );


        if (!enabled) {

            throw new Error(
                'Control.Write.Enabled ist AUS.'
            );
        }


        // -------------------------------------------------------------
        // Busy nochmals serverseitig prüfen
        // -------------------------------------------------------------

        const busy =
            truthy(
                await stateVal(
                    WRITE_BUSY,
                    false
                )
            );


        if (busy) {

            throw new Error(
                'MB-Secure Write-Control ist beschäftigt.'
            );
        }


        const oldLastTime =
            await stateVal(
                WRITE_LAST_TIME,
                ''
            );


        // -------------------------------------------------------------
        // Parameter setzen
        // -------------------------------------------------------------

        await setStateAsync(
            WRITE_COMMAND,
            command,
            true
        );


        await setStateAsync(
            WRITE_TARGET,
            uid,
            true
        );


        await setStateAsync(
            DP_LAST_ACTION,
            `${new Date().toLocaleString('de-DE')} · ${command} · UID ${uid}`,
            true
        );


        await setStateAsync(
            DP_ACTION_RESULT,
            `Befehl übergeben: ${command} / UID ${uid}`,
            true
        );


        // -------------------------------------------------------------
        // Execute bewusst ACK=false
        // -------------------------------------------------------------

        await setStateAsync(
            WRITE_EXECUTE,
            true,
            false
        );


        // -------------------------------------------------------------
        // Abschluss abwarten
        // -------------------------------------------------------------

        const completed =
            await waitForWriteCompletion(
                oldLastTime
            );


        if (!completed) {

            throw new Error(
                'Timeout: Write-Control meldete innerhalb von 45 Sekunden keinen abgeschlossenen Schreibvorgang.'
            );
        }


        // -------------------------------------------------------------
        // Readback kontrollieren
        // -------------------------------------------------------------

        const verified =
            truthy(
                await stateVal(
                    WRITE_VERIFIED,
                    false
                )
            );


        const verification =
            String(
                await stateVal(
                    WRITE_VERIFICATION,
                    ''
                )
            );


        const writeError =
            String(
                await stateVal(
                    WRITE_ERROR,
                    ''
                )
            );


        const lastCommand =
            String(
                await stateVal(
                    WRITE_LAST_COMMAND,
                    ''
                )
            );


        // -------------------------------------------------------------
        // LastCommand muss zum gerade gesendeten Befehl passen.
        // Format kann Zusatztext enthalten, deshalb kein striktes ===.
        // -------------------------------------------------------------

        if (
            lastCommand &&
            !lastCommand.includes(command)
        ) {

            throw new Error(
                `Unerwarteter Write-Readback: ${lastCommand}`
            );
        }


        if (!verified) {

            throw new Error(
                writeError ||
                verification ||
                'Schreibbefehl wurde nicht per Readback bestätigt.'
            );
        }


        await setStateAsync(
            DP_ACTION_RESULT,
            `OK: ${command} / UID ${uid}${
                verification
                    ?
                    ` · ${verification}`
                    :
                    ''
            }`,
            true
        );


    } catch (e) {

        await setStateAsync(
            DP_ACTION_RESULT,
            `Fehler: ${e.message}`,
            true
        );


        log(
            `[MB-Secure Dashboard] Aktion fehlgeschlagen: ${
                e.stack ||
                e.message ||
                e
            }`,
            'error'
        );


    } finally {

        actionRunning =
            false;


        scheduleRender();
    }
}


// =====================================================================
// START
// =====================================================================

(async () => {

    try {

        log(
            `[MB-Secure Dashboard] v${VERSION} startet.`,
            'info'
        );


        // -------------------------------------------------------------
        // Dashboard States
        // -------------------------------------------------------------

        await ensureState(
            DP_HTML,
            '',
            'string',
            'MB-Secure VIS2 Dashboard HTML'
        );


        await ensureState(
            DP_ACTION,
            '',
            'string',
            'MB-Secure Dashboard Aktion',
            true,
            'text'
        );


        await ensureState(
            DP_ACTION_RESULT,
            '',
            'string',
            'MB-Secure Dashboard Aktion Ergebnis'
        );


        await ensureState(
            DP_LAST_ACTION,
            '',
            'string',
            'MB-Secure Dashboard letzte Aktion'
        );


        await ensureState(
            DP_LAST_RENDER,
            '',
            'string',
            'MB-Secure Dashboard letzte Aktualisierung'
        );


        // -------------------------------------------------------------
        // Dashboard Bedienaktion
        // -------------------------------------------------------------

        on(
            {
                id: DP_ACTION,

                change: 'ne'
            },

            handleAction
        );


        // -------------------------------------------------------------
        // Mirror-/Write-Änderungen -> neu rendern
        // -------------------------------------------------------------

        on(
            {
                id:
                    new RegExp(
                        '^' +
                        ROOT.replace(
                            /\./g,
                            '\\.'
                        ) +
                        '\\.(Partitions|DetectorGroups|Outputs|System|Info|Control\\.Write)\\.'
                    ),

                change: 'ne'
            },

            scheduleRender
        );


        // -------------------------------------------------------------
        // Erster Aufbau
        // -------------------------------------------------------------

        await renderDashboard();


        // -------------------------------------------------------------
        // Sicherheits-Refresh alle fünf Minuten
        // -------------------------------------------------------------

        schedule(
            '*/5 * * * *',
            renderDashboard
        );


        log(
            `[MB-Secure Dashboard] v${VERSION} gestartet.`,
            'info'
        );


    } catch (e) {

        log(
            `[MB-Secure Dashboard] STARTFEHLER: ${
                e.stack ||
                e.message ||
                e
            }`,
            'error'
        );
    }

})();