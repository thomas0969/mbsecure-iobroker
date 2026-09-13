# Installation

## 1. Voraussetzungen

- laufende MB-Secure mit erreichbarer HTTPS-Service-Schnittstelle
- gültiger Service-Benutzer
- ioBroker mit JavaScript-Adapter
- VIS2, für das Dashboard zusätzlich Material Widgets
- Netzwerkzugriff vom ioBroker-Host zur MB-Secure

Das Projekt wurde mit Firmware `EMBSC.00.0V12.55` entwickelt. Andere Firmwarestände sind nicht automatisch als kompatibel anzusehen.

## 2. AutoMirror installieren

Datei `src/MBSecure_AutoMirror.js` als neues JavaScript in ioBroker anlegen.

Im Kopf des Skripts den `CFG`-Block anpassen:

```js
const CFG = {
    host: '192.168.1.100',
    port: 444,
    base: '0_userdata.0.MBSecure',
    username: 'iobroker',
    password: 'HIER_DEIN_PASSWORT_EINTRAGEN',
    // ...
};
```

Das Passwort liegt damit im ioBroker-Skript und kann auch in Backups enthalten sein. Repository, Screenshots, Exporte und Support-Anfragen daher vor Veröffentlichung prüfen.

## 3. Erster Start

Browser-Service-Sitzungen zur MB-Secure vorher schließen, da die Service-Schnittstelle je nach Zustand nur eine nutzbare Sitzung zulassen kann.

Nach dem Start sollten im Log mindestens folgende Schritte erscheinen:

```text
[MB-Secure] Login OK: ...
[MB-Secure] FullSync gestartet: Scriptstart
[MB-Secure] FullSync erfolgreich: ...
[MB-Secure] SSE verbunden
```

Erst wenn der FullSync erfolgreich abgeschlossen wurde, mit Schreibtests fortfahren.

## 4. Dashboard installieren

`src/MBSecure_Dashboard.js` als zweites ioBroker-JavaScript anlegen und starten.

Das Dashboard erzeugt unter anderem:

```text
0_userdata.0.MBSecure.Dashboard.HTML
0_userdata.0.MBSecure.Dashboard.Action
0_userdata.0.MBSecure.Dashboard.ActionResult
```

## 5. VIS2-Widget

In VIS2 ein Widget **Material Widgets → HTML-Vorlage** einfügen.

HTML-Inhalt:

```text
{0_userdata.0.MBSecure.Dashboard.HTML.val}
```

Empfohlene Widget-Geometrie:

```text
position: absolute
left: 0px
top: 0px
width: 100%
height: 100%
overflow-x: hidden
overflow-y: auto
```

Das Dashboard selbst ist intrinsisch responsiv und verwendet keine feste Desktopbreite.

## 6. Schreibfunktionen testen

Empfohlene Reihenfolge:

1. Bedienung im Dashboard freigeben.
2. unkritische Meldergruppe intern sperren und wieder freigeben.
3. extern sperren und wieder freigeben.
4. intern **und** extern gleichzeitig sperren und beide Zustände prüfen.
5. erst danach Bereich löschen / intern scharf / unscharf / extern scharf / unscharf testen.

Jeder Schreibbefehl wird vom AutoMirror rückgelesen. Ein bloßes API-`Result=OK` gilt nicht als ausreichende Bestätigung.
