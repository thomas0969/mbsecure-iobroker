# Architektur

## Komponenten

### AutoMirror

Der AutoMirror ist die einzige Komponente, die direkt mit der MB-Secure kommuniziert. Er übernimmt:

- Login und Session-ID
- Keepalive
- FullSync
- SSE-Verbindung
- inkrementelle Aktualisierung
- Spiegelung in ioBroker-Datenpunkte
- kontrollierte Schreibbefehle
- Readback-Verifikation
- Login-Sperre nach Authentifizierungsfehlern

### Dashboard

Das Dashboard liest ausschließlich ioBroker-Datenpunkte und erzeugt HTML für VIS2. Es hat keine Panel-Zugangsdaten und keinen direkten Netzwerkzugriff zur Zentrale.

Bedienaktionen werden als Dashboard-Aktion in ioBroker geschrieben. Der Dashboard-Backendteil validiert Befehl und Ziel und übergibt sie an `Control.Write`.

## Datenfluss Lesen

```text
MB-Secure
   ↓ HTTPS / SSE
AutoMirror
   ↓
0_userdata.0.MBSecure.*
   ↓
Dashboard-Skript
   ↓
Dashboard.HTML
   ↓
VIS2
```

## Datenfluss Schreiben

```text
VIS2-Klick
   ↓
Dashboard.Action
   ↓ Validierung
Control.Write.Command + TargetUID + Execute
   ↓
AutoMirror
   ↓ Sicherheits-/Zustandsprüfung
MB-Secure
   ↓
Readback
   ↓
LastVerified / LastVerification / LastError
```

## Change-only-Mirroring

Version 2.1.1 führte ein Change-only-Verfahren ein. Unveränderte, bereits bestätigte (`ack=true`) Werte werden nicht erneut mit `setState()` geschrieben. Dadurch wurde die ioBroker-Sicherheitsabschaltung bei mehr als 1000 `setState`-Aufrufen pro Minute verhindert.

## Meldergruppen-Sperren

Die MB-Secure kann eine Gruppe intern und extern unabhängig sperren. `otAlwaysPartSet` wird deshalb als kombinierter Zustand ausgewertet:

```text
InternalBlocked = true
ExternalBlocked = true
```

Dashboard 1.3.1 behandelt beide Schalter unabhängig.
