# MB-Secure ↔ ioBroker

Lokale Integration einer **Honeywell / Novar MB-Secure** in **ioBroker** über die vorhandene Service-Schnittstelle der Zentrale.

Das Projekt besteht aus zwei vollständigen ioBroker-JavaScript-Skripten:

- **AutoMirror 2.1.2** – liest die MB-Secure aus, spiegelt Zustände nach `0_userdata.0.MBSecure` und stellt ausgewählte, rückgelesene Schreibfunktionen bereit.
- **VIS2 Dashboard 1.3.1** – responsives Bedienpanel für Bereiche und Meldergruppen. Das Dashboard spricht die Zentrale **niemals direkt** an, sondern ausschließlich über die kontrollierte Write-Schicht des AutoMirror.

> **Projektstatus:** Abgeschlossenes Community-/Privatprojekt. Es besteht kein Anspruch auf Support, Weiterentwicklung oder Kompatibilität mit zukünftigen Firmware-, ioBroker- oder VIS2-Versionen.

## Funktionen

- automatische Anmeldung an der MB-Secure Service-Schnittstelle
- vollständiger und ereignisbasierter Abgleich
- SSE-Verbindung für zeitnahe Aktualisierung
- 5-Minuten-Sperre nach echter Login-Ablehnung
- ressourcenschonendes Change-only-Mirroring
- Bereiche, Meldergruppen, Member, Ausgänge, Makros, Benutzer und Netzteile einlesen
- Alarmklassen spiegeln
- responsive VIS2-Oberfläche für Desktop, Tablet und Smartphone
- interne und externe Sperrung von Meldergruppen **unabhängig und gleichzeitig**
- einmaliges Übergehen (Bypass)
- Bereich löschen
- intern scharf / extern scharf / unscharf
- Ausgänge schalten, sofern vom Mirror erkannt
- jeder freigegebene Schreibbefehl wird anschließend rückgelesen und verifiziert

## Getesteter Stand

Entwickelt und praktisch getestet mit:

- MB-Secure Firmware: `EMBSC.00.0V12.55`
- ioBroker JavaScript-Adapter
- VIS2 Material Widgets → HTML-Vorlage

Andere Firmwarestände können sich anders verhalten. Insbesondere Schreibbefehle sollten an einer Testanlage geprüft werden, bevor sie produktiv eingesetzt werden.

## Schnellstart

1. `src/MBSecure_AutoMirror.js` in ioBroker JavaScript importieren.
2. Im `CFG`-Block IP-Adresse, Port, Benutzername und Passwort anpassen.
3. Mirror starten und einen erfolgreichen Login sowie FullSync abwarten.
4. `src/MBSecure_Dashboard.js` als zweites ioBroker-JavaScript importieren und starten.
5. In VIS2 ein **Material Widgets → HTML-Vorlage** Widget anlegen.
6. Als Inhalt verwenden:

```text
{0_userdata.0.MBSecure.Dashboard.HTML.val}
```

7. Das Widget auf `width: 100%`, `height: 100%`, `overflow-x: hidden`, `overflow-y: auto` stellen.
8. Schreibfunktionen erst nach erfolgreichem Lese-/Status-Test über **Bedienung freigeben** aktivieren.

Die vollständige Anleitung steht unter [docs/INSTALLATION.md](docs/INSTALLATION.md).

## Sicherheitsprinzip

Das Dashboard besitzt keinen eigenen Zugang zur Alarmzentrale. Bedienbefehle laufen über:

```text
VIS2
  ↓
Dashboard.Action
  ↓
Control.Write
  ↓
AutoMirror
  ↓
MB-Secure
  ↓
Readback / Verifikation
```

Damit werden UI, Freigabe, Sicherheitsprüfungen und tatsächlicher Panelzugriff getrennt.

## Verifizierte Schreibfunktionen

| Funktion | Status |
|---|---|
| Bereich löschen / Supervisor Clear | praktisch verifiziert |
| Unscharf | praktisch verifiziert |
| Intern scharf | praktisch verifiziert |
| Extern scharf | praktisch verifiziert |
| Meldergruppe intern sperren | praktisch verifiziert |
| Meldergruppe extern sperren | praktisch verifiziert |
| Intern + extern gleichzeitig sperren | praktisch verifiziert |
| Sperren wieder aufheben | praktisch verifiziert |
| Einmalig übergehen / Bypass | praktisch verifiziert |
| Normalen Ausgang EIN/AUS | praktisch verifiziert |

Nicht freigegebene bzw. nicht ausreichend getestete API-Funktionen werden bewusst nicht als Bedienfunktion angeboten.

## Alarmklassen

`atIntruder` und `atTamper` wurden praktisch verifiziert. Weitere von der API gelieferte Alarmklassen werden gespiegelt, sind aber nicht alle einzeln mit realer Hardware ausgelöst worden. Ein nicht sicher identifizierter „Internalarm/Voralarm“ wird bewusst **nicht erfunden oder geraten**.

## Repository-Struktur

```text
.
├── src/
│   ├── MBSecure_AutoMirror.js
│   └── MBSecure_Dashboard.js
├── docs/
├── screenshots/
├── .github/
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
└── package.json
```

## Wichtiger Hinweis

Dies ist **kein offizielles Honeywell-/Novar-Projekt**. Es nutzt die vorhandene Service-Schnittstelle einer MB-Secure. Die kostenpflichtige offizielle Fremdschnittstelle ist ein separates Produkt und wird durch dieses Projekt weder vorausgesetzt noch umgangen.

Die Nutzung erfolgt auf eigene Verantwortung. Bei einer Einbruchmeldeanlage können Fehlbedienungen reale Sicherheitsfolgen haben. Vor produktivem Einsatz Backup, Testbetrieb und Rückleseprüfung durchführen.

## Lizenz

MIT – siehe [LICENSE](LICENSE).
