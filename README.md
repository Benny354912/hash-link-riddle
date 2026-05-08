# [Hash-Link-Riddle](https://benny354912.github.io/hash-link-riddle/)

Ein minimalistisches, clientseitiges Tool zum Erstellen und Teilen von Hash-Challenges.

Du gibst eine geheime Eingabe ein, die App erzeugt daraus sofort eine teilbare URL mit Hash-Fragment. Wer den Link öffnet, kann Eingaben testen, bis dieselbe Hash-Ausgabe entsteht.  
Kein Backend, keine externe Speicherung.

## Funktionsweise

1. Ersteller gibt eine geheime Eingabe ein.
2. Die App erzeugt in Echtzeit eine URL mit allen nötigen Parametern im Fragment.
3. Empfänger öffnet die URL und testet Eingaben.
4. Bei jeder Eingabeänderung wird sofort geprüft:
   - 1:1 Eingabe
   - lowercase Eingabe

## Unterstützte Hash-Verfahren

- SHA-256
- MD5
- PBKDF2-SHA-256 (Password Hash)
- PBKDF2-SHA-512 (Password Hash)

Hinweis: MD5 ist aus Sicherheits-Sicht veraltet und hauptsächlich für Kompatibilität/Tests enthalten.

## Optionen

| Option | Beschreibung |
|---|---|
| Hash-Verfahren | Auswahl des gewünschten Verfahrens für die Challenge-Erstellung. |
| Groß/Klein beachten | Aktiv: Originaltext wird gehasht. Inaktiv: Eingabe wird vor dem Hashing in Kleinbuchstaben umgewandelt. |
| Sicheres Salt verwenden | Für schnelle Verfahren optional aktivierbar. Für PBKDF2 immer aktiv und verpflichtend. |
| Salt neu erzeugen | Erzeugt ein neues kryptografisch sicheres Salt für die aktuelle Challenge. |

## URL-Format

Die URL speichert alle nötigen Daten im Fragment ohne Versionsparameter:

- a: Algorithmus
- c: Case-Flag (1 oder 0)
- h: Ziel-Hash
- s: Salt (optional bei schnellen Verfahren, verpflichtend bei PBKDF2)
- i: Iterationen (bei PBKDF2)

Beispielstruktur:  
#a=pbkdf2-sha256&c=1&h=...&s=...&i=180000

Legacy-Links aus älteren Versionen werden weiterhin gelesen.

## Technik

- Reines Frontend: HTML, CSS, JavaScript
- SHA und PBKDF2 über Web Crypto API: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
- MD5 als clientseitige JavaScript-Implementierung
- Salt-Erzeugung über crypto.getRandomValues
- Keine externen Abhängigkeiten, kein Build-Schritt
- Funktioniert lokal über file und auf statischem Hosting

## Starten

Einfach [index.html](https://benny354912.github.io/hash-link-riddle/) im Browser öffnen.

## Lizenz

© 2026 Benny354912
