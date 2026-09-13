# Fehlerbehebung

## Login funktioniert nicht

- IP, Port, Benutzername und Passwort prüfen.
- Prüfen, ob bereits eine Browser-/Service-Sitzung aktiv ist.
- Bei echter Login-Ablehnung blockiert der Mirror weitere Loginversuche lokal für fünf Minuten. Das verhindert eine schnelle Folge weiterer Authentifizierungsversuche.

## Dashboard zeigt Offline

Prüfen:

```text
0_userdata.0.MBSecure.System.Connected
```

Außerdem im Mirror-Log nach erfolgreichem Login, FullSync und SSE-Verbindung suchen.

## Dashboard-Aktion passiert nicht

Prüfen:

```text
0_userdata.0.MBSecure.Control.Write.Enabled
0_userdata.0.MBSecure.Control.Write.Command
0_userdata.0.MBSecure.Control.Write.TargetUID
0_userdata.0.MBSecure.Control.Write.Execute
0_userdata.0.MBSecure.Control.Write.Busy
0_userdata.0.MBSecure.Control.Write.LastError
0_userdata.0.MBSecure.Control.Write.LastVerification
```

## `Script is calling setState more than 1000 times per minute`

Ab AutoMirror 2.1.1 werden unveränderte bestätigte Werte nicht erneut geschrieben. Falls diese Meldung mit einer späteren Version erneut erscheint, nicht einfach das ioBroker-Limit erhöhen. Zuerst die Ursache der Schreibschleife ermitteln.

## Intern und extern gleichzeitig gesperrt

Ab AutoMirror 2.1.2 / Dashboard 1.3.1 wird ein kombinierter Sperrzustand korrekt unterstützt. Ältere Dashboard-Versionen behandelten die beiden Schalter fälschlich als gegenseitig ausschließend.

## FullSync dauert einige Sekunden

Das ist erwartbar. Der Mirror fragt mehrere Objektklassen ab und verzögert Requests bewusst. Entscheidend ist, dass der FullSync erfolgreich endet und der JavaScript-Adapter das Skript nicht wegen übermäßiger `setState`-Last beendet.
