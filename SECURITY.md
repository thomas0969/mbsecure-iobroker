# Security Policy

## Zugangsdaten niemals veröffentlichen

Bitte keine echten MB-Secure-Zugangsdaten, Session-IDs, Backups, internen Netzpläne oder vollständigen Anlagenexporte in öffentliche Issues oder Commits einstellen.

Der AutoMirror enthält das Service-Passwort bewusst im lokalen ioBroker-Skript. Vor GitHub-Upload muss der Wert auf den Platzhalter zurückgesetzt sein:

```text
HIER_DEIN_PASSWORT_EINTRAGEN
```

## Sicherheitsrelevante Meldungen

Sicherheitsprobleme bitte nicht mit realen Zugangsdaten oder detaillierten produktiven Anlageninformationen in einem öffentlichen Issue demonstrieren. Stattdessen einen minimalen, anonymisierten Reproduktionsfall verwenden.

Falls Zugangsdaten versehentlich veröffentlicht wurden:

1. Passwort an der Zentrale ändern.
2. Geheimnis aus der Git-Historie entfernen, nicht nur aus dem aktuellen Commit.
3. ggf. veröffentlichte Backups/Artefakte ebenfalls ersetzen.

## Bedrohungsmodell

Dieses Projekt ist keine zertifizierte Alarmanlagen-Schnittstelle. Ein kompromittierter ioBroker-Host oder ein Benutzer mit Schreibzugriff auf die relevanten Datenpunkte kann sicherheitsrelevante Bedienaktionen anstoßen. ioBroker, VIS2 und Netzwerksegmentierung daher entsprechend absichern.
