# Schreibbefehle

Das Projekt stellt nur Befehle bereit, deren Semantik praktisch getestet oder ausreichend abgesichert wurde.

| Interner Befehl | Bedeutung |
|---|---|
| `PARTITION_CLEAR` | Bereich löschen / Supervisor Clear |
| `PARTITION_UNSET` | unscharf |
| `PARTITION_PARTSET` | intern scharf |
| `PARTITION_FULLSET` | extern scharf |
| `GROUP_OMIT_PART` | intern sperren |
| `GROUP_UNOMIT_PART` | interne Sperre aufheben |
| `GROUP_OMIT_ALWAYS` | extern sperren |
| `GROUP_UNOMIT_ALWAYS` | externe Sperre aufheben |
| `GROUP_BYPASS_ON` | einmalig übergehen |
| `GROUP_BYPASS_OFF` | Übergehen aufheben |
| `OUTPUT_ON` | normaler Ausgang EIN |
| `OUTPUT_OFF` | normaler Ausgang AUS |

## Grundsatz: Readback statt blindem Erfolg

Ein API-Ergebnis `OK` beweist nicht, dass der erwartete Anlagenzustand tatsächlich erreicht wurde. Der AutoMirror liest deshalb nach einem Schreibbefehl den Zustand erneut ein und bewertet erst den Readback als Erfolg.

## Bereich löschen

`PARTITION_CLEAR` ist auf den unscharfen Bereich beschränkt. In praktischen Tests musste ein Bereich mit ausgelösten/gestörten relevanten Gruppen zunächst passend gesperrt werden, bevor Supervisor Clear den Bereich wieder in einen schaltbereiten Zustand brachte.

## Bypass

Bypass ist als einmaliges Übergehen gedacht. Das Einschalten wird nur zugelassen, wenn die Gruppe nicht im Alarm steht und der Bereich unscharf ist. Nach Unscharfschaltung kann der Bypass durch die Zentrale automatisch verschwinden.

## Nicht freigegeben

Bewusst nicht als Produktions-Schreibfunktion angeboten:

- Revision/Test/Störung
- `Activate/Deactivate`
- DetectorGroup `OutputOn/Off`
- Makro-/Benutzer-Schreibbefehle ohne ausreichend getestetes Testobjekt
