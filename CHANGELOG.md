# Changelog

## AutoMirror 2.1.2 / Dashboard 1.3.1 — 2026-09-13

- kombinierte interne + externe Meldergruppensperre (`otAlwaysPartSet`) korrekt ausgewertet
- interne und externe Sperre im Dashboard unabhängig bedienbar
- kombinierter Status im Dashboard darstellbar

## AutoMirror 2.1.1 / Dashboard 1.3.0 — 2026-09-13

- Change-only-Mirroring eingeführt
- unveränderte `ack=true`-States werden nicht erneut geschrieben
- Sensor-`LastUpdate` nur noch bei tatsächlicher Änderung/Erstanlage
- ioBroker-Abschaltung durch >1000 `setState`/min behoben
- Dashboard ohne `<script>`-Block und ohne globale Browser-Hilfsfunktionen
- VIS2-Aktionen direkt über `vis.setValue(...)`
- responsives, intrinsisches Layout

## AutoMirror 2.1.0

- vollständige Read/Write-Schicht mit Readback-Verifikation
- Login-Sperre nach Authentifizierungsablehnung
- Write-Control für Dashboard-Bedienung
- Bereiche, Gruppen, Ausgänge und weitere Anlagenobjekte
- SSE-Ereignisverarbeitung
