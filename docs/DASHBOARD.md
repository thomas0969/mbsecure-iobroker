# VIS2 Dashboard

Version 1.3.1 erzeugt ein vollständiges responsives Anlagenpanel als HTML-Datenpunkt.

## Eigenschaften

- keine feste Desktopbreite
- keine festen Desktop-/Tablet-/Mobil-Spalten
- automatische Spaltenzahl über `auto-fit/minmax`
- kein horizontaler Scrollzwang
- lange Namen dürfen umbrechen
- Bereiche auf-/zuklappbar
- Meldergruppen mit Status und Sperr-/Bypass-Schaltern
- interne und externe Sperre gleichzeitig darstellbar
- Bedienfreigabe zentral im Kopf

## Keine Browser-Hilfsfunktionen

Das erzeugte HTML enthält keinen eigenen `<script>`-Block und keine globalen `window.mbSec...`-Funktionen. Aktionen verwenden direkt `vis.setValue(...)`. Dadurch bleibt das Widget kompatibler mit VIS2.

## Dashboard-Datenpunkte

Wesentliche Datenpunkte:

```text
0_userdata.0.MBSecure.Dashboard.HTML
0_userdata.0.MBSecure.Dashboard.Action
0_userdata.0.MBSecure.Dashboard.ActionResult
0_userdata.0.MBSecure.Dashboard.LastAction
0_userdata.0.MBSecure.Dashboard.LastRender
```

Schreibaktionen werden nicht direkt zur Zentrale geschickt, sondern in die `Control.Write`-Struktur des AutoMirror übergeben.
