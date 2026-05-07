# Hash-Link-Riddle

Ein minimalistisches, clientseitiges Tool zum Erstellen und Teilen von Hash-Challenges.

Du gibst eine geheime Eingabe ein – die App erzeugt daraus eine SHA-256-Hash-URL, die du teilen kannst. Wer den Link öffnet, sieht nur das Eingabefeld und muss die richtige Eingabe erraten, die denselben Hash erzeugt. Kein Backend, keine Daten werden übertragen.

## Funktionsweise

1. **Ersteller** gibt eine geheime Eingabe ein.
2. Die App erzeugt sofort eine teilbare URL mit dem SHA-256-Hash als Fragment (`#`).
3. **Empfänger** öffnet die URL und testet Eingaben – bei jedem Tastendruck wird geprüft, ob die Eingabe (1:1 oder lowercase) denselben Hash erzeugt.

Der Ziel-Hash verlässt den Browser nie im Klartext.

## Optionen

| Option | Beschreibung |
|---|---|
| Groß/Klein beachten | Aktiv: Originaltext wird gehasht. Inaktiv: Eingabe wird vor dem Hashing in Kleinbuchstaben umgewandelt. |

## Technik

- Reines Frontend – HTML, CSS, JavaScript
- Hash-Verfahren: **SHA-256** via [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest)
- Keine externen Abhängigkeiten, kein Build-Schritt
- Funktioniert lokal über `file://` sowie auf jedem statischen Hosting

## Starten

Einfach `index.html` im Browser öffnen – fertig.

## Lizenz

© 2026 Benny354912
