# Konfiguration

Die zentrale Konfiguration befindet sich am Anfang von `src/MBSecure_AutoMirror.js`.

## Wesentliche Parameter

| Parameter | Bedeutung |
|---|---|
| `host` | IP-Adresse oder Hostname der MB-Secure |
| `port` | HTTPS-Port der Service-Schnittstelle, im getesteten System `444` |
| `base` | ioBroker-Datenpunktwurzel, Standard `0_userdata.0.MBSecure` |
| `username` | Service-Benutzer |
| `password` | Service-Passwort im Klartext innerhalb des ioBroker-Skripts |
| `requestTimeoutMs` | Timeout einzelner HTTPS-Anfragen |
| `keepaliveMs` | Session-Keepalive |
| `configPollMs` | Polling für Konfigurations-/Änderungsstatus |
| `fullSyncMs` | Intervall des vollständigen Abgleichs |
| `sseReconnectMs` | Wartezeit vor SSE-Neuverbindung |
| `loginRejectBlockMs` | lokale Sperrzeit nach echter Login-Ablehnung |
| `writeVerifyDelayMs` | Wartezeit vor Schreib-Readback |
| `writeVerifyTries` | maximale Readback-Versuche |
| `debug` | zusätzliche Debug-Ausgaben |

## Passwort

Das Projekt verwendet bewusst keine externe Secrets-Datei, damit ein einzelnes ioBroker-Skript reproduzierbar bleibt. Das ist bequem, bedeutet aber: Das Passwort kann in ioBroker-Backups oder exportierten Skripten enthalten sein.

Vor einer Veröffentlichung muss `password` auf

```text
HIER_DEIN_PASSWORT_EINTRAGEN
```

zurückgesetzt werden.
