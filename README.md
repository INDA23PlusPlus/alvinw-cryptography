# alvinw-cryptography
An encrypted remote file storage.

Filer krypteras med AES-GCM, då det enligt föreläsningen var en bra algoritm för symmetrisk kryptering.

Ett Merkle-träd används för att verifiera att alla filer som lagras är giltiga. Hashfunktionen som används är SHA-256 då det är en välkänd hashfunktion som fungerar bra, och som även rekomenderades på hackmd.

Fil-idt är också en SHA-256 hash av filnamnet.

För signering används RSA. Första gången programmet körs kommer en RSA-keypair att skapas.

Filerna får en header enligt följande:

|                         | size                     |
|-------------------------|--------------------------|
| signature length        | 4 bytes                  |
| signature*              | *signature length* bytes |
| nonce                   | 16 bytes                 |
| iv                      | 12 bytes                 |
| timestamp               | 8 bytes                  |
| file content ciphertext | remaining bytes          |

*The signature signs the SHA-256 hash of the nonce, iv, timestamp and file content ciphertext.

The Merkle-tree on the other hand signs the entire file contents. Oops nu bytte jag språk mitt i.

## Användning
Kör `Server`-klassen för att starta servern.

Kör sedan `Client`-klassen. Du blir promptad vad du vill göra, t.ex. `upload`, `read` och `verify`.
För att ladda upp en fil, skriv `upload` + enter och sen kan du skriva in sökväg till en fil var som helst på din dator. Notera att bara filnamnet kommer användas för att skapa fil-idt. Så om du sedan vill läsa filen, skriv bara filnamnet, inte hela sökvägen.

<hr>

Koden är inte så effektivt skriven, bytes kopieras i onödan massa gånger och ingenting streamas utan allt bara läses in i minne. Koden är inte särskilt bra skriven heller, men funkar.