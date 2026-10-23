# safemaxxing

[![CI](https://github.com/carlobaratta/safemaxxing/actions/workflows/ci.yml/badge.svg)](https://github.com/carlobaratta/safemaxxing/actions/workflows/ci.yml)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![macOS](https://img.shields.io/badge/platform-macOS-lightgrey)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Privacy supervisor ed egress firewall headless per macOS, basato su correlazione di eventi.**

LuLu e Little Snitch ti chiedono *"questa app può connettersi a X?"*. safemaxxing risponde a
una domanda diversa: **"questa app ha appena acceso la fotocamera e, nei 2 secondi successivi,
ha aperto un socket verso Internet?"**

Rileva la catena causa → effetto tipica dell'esfiltrazione:

```
 [Sensore]  kTCCServiceCamera  pid=4242 com.example.spy      t = 0 ms
     │
     ▼  finestra di correlazione (default 2000 ms)
 [Egress]   tcp 10.0.0.5:51544 -> 203.0.113.9:443 pid=4242   t = 87 ms
     │
     ▼
 [Alert]    #1 [high] com.example.spy used camera then connected to 203.0.113.9:443 after 87 ms
     │
     ├── b  → pfctl -a com.apple/safemaxxing -t safemaxxing_block -T add 203.0.113.9
     ├── s  → SIGSTOP 4242   (r → SIGCONT)
     └── k  → SIGKILL 4242
```

> **Stato:** alpha (0.1.0). Validato su macOS 27.0.1, Apple Silicon (vedi
> [TESTLOG.md](TESTLOG.md)); test unitari in CI su macOS arm64 e Intel. Gira come root e
> modifica pf: leggi [SECURITY.md](SECURITY.md) prima di usare le azioni automatiche.

## Indice

- [Funzionalità](#funzionalità)
- [Installazione](#installazione)
- [Utilizzo](#utilizzo)
- [Architettura](#architettura)
- [Limiti noti](#limiti-noti)
- [Sviluppo](#sviluppo)
- [Documentazione del progetto](#documentazione-del-progetto)

## Funzionalità

- **Sensori**: un `log stream --style json` asincrono con predicati su `com.apple.TCC`
  (righe `kTCCService*`) e su `com.apple.controlcenter` (categoria `sensor-indicators`).
  Filtra per parole chiave anche `com.apple.locationd*`, `com.apple.coreaudio*` e
  `com.apple.cmio*`.
  - Classifica Fotocamera, Microfono, Posizione, Screen Capture e qualunque altro servizio
    TCC.
  - Attribuisce l'accesso al PID e al bundle id del *client*, non ai daemon broker come
    `tccd`, `coreaudiod` o `sandboxd`.
  - La fonte principale sono le attribuzioni dell'indicatore di privacy di Control Center
    (`Active activity attributions changed to ["cam:…", "mic:…", "loc:…"]`), verificate su
    macOS 27.
  - Screen Capture conta solo quando è il processo che cattura a registrare la propria
    richiesta: i preflight di WindowServer e `coreaudiod` per conto di altre app vengono
    scartati.
  - Sono scartati anche i controlli `com.apple.private.tcc.manager` che i daemon fanno per
    conto di altri.
- **Socket mapper**: polling della tabella socket via `psutil`, con fallback `lsof -F`.
  - Tiene solo le connessioni *in uscita*: TCP `SYN_SENT`/`ESTABLISHED` non accettate su porte
    in ascolto, e UDP connessi.
  - Ricava il bundle id dall'`Info.plist` dell'app.
  - Fa il reverse DNS in background, con cache.
- **Correlazione**: buffer circolari in memoria per eventi e connessioni.
  - Fa il match per PID o per bundle id, inclusi gli helper (es. `com.google.Chrome.helper`).
  - La finestra è configurabile e tollera clock skew e righe di log arrivate in ritardo.
  - Produce un solo alert per connessione: se altri sensori la precedono, l'alert viene
    aggiornato con lo stesso id. Cooldown di 30 s per (pid, sensore, IP).
  - Le raffiche di righe di log di un accesso diventano un solo evento.
  - La severità base è `high` (`medium` per gli altri servizi TCC). Sale di un livello, fino a
    `critical`, se più sensori diversi precedono la stessa connessione.
- **Enforcement**: tabella pf `safemaxxing_block` dentro l'anchor `com.apple/safemaxxing`.
  L'anchor è già valutato dal `/etc/pf.conf` di sistema, quindi non serve modificare la
  configurazione. Controllo dei processi con `SIGSTOP` / `SIGCONT` / `SIGKILL`.
- **TUI Textual**: alert, connessioni attive e stream degli eventi sensore in tempo reale.
- **Headless**: `safemaxxing watch` con output JSON lines e azioni automatiche opzionali.

## Installazione

Requisiti: macOS (Apple Silicon o Intel), Python 3.12+, [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/carlobaratta/safemaxxing
cd safemaxxing
uv sync
sudo uv run safemaxxing doctor
```

## Utilizzo

```bash
sudo uv run safemaxxing tui                       # dashboard interattiva
sudo uv run safemaxxing tui --window-ms 800 --ignore com.apple.FaceTime

sudo uv run safemaxxing watch --json              # headless, JSON lines su stdout
sudo uv run safemaxxing watch --auto-block --min-severity high

sudo uv run safemaxxing block 203.0.113.9
sudo uv run safemaxxing blocked
sudo uv run safemaxxing unblock 203.0.113.9
sudo uv run safemaxxing flush

sudo uv run safemaxxing freeze 4242               # SIGSTOP
sudo uv run safemaxxing thaw 4242                 # SIGCONT
sudo uv run safemaxxing kill 4242                 # SIGKILL

uv run safemaxxing version
```

Root serve per vedere i socket di altri utenti, leggere tutti i log TCC, usare `pfctl` e
inviare segnali a processi altrui. Senza root safemaxxing funziona in modalità degradata.
`uv run safemaxxing <comando> --help` mostra tutte le opzioni.

### Opzioni di `tui` e `watch`

| Opzione | Default | Effetto |
|---------|---------|---------|
| `--window-ms N` | `2000` | Finestra di correlazione sensore → egress |
| `--poll-ms N` | `200` | Intervallo di polling della tabella socket (min 20) |
| `--ignore ID` | — | Bundle id o nome processo da ignorare (match esatto, ripetibile) |
| `--include-system` | off | Mostra gli eventi dei binari di sistema e correla anche i loro socket |
| `--include-dns` | off | Alert anche sulle risoluzioni DNS (porte 53/853/5353) |
| `--include-loopback` | off | Traccia anche `127.0.0.1` / `::1` |
| `--no-dns` | off | Disattiva il reverse DNS |

Solo per `watch`:

| Opzione | Default | Effetto |
|---------|---------|---------|
| `--json` | off | Alert come JSON lines |
| `--events` | off | Stampa anche gli eventi sensore (ignorato con `--json`) |
| `--auto-block` | off | Blocca l'IP di destinazione degli alert sopra soglia |
| `--auto-suspend` | off | `SIGSTOP` sul processo degli alert sopra soglia |
| `--min-severity S` | `high` | Soglia per `--auto-*`: `low`, `medium`, `high`, `critical`. Ogni alert agisce al massimo una volta |

### Tasti della TUI

| Tasto | Azione |
|-------|--------|
| `b` / `u` | Blocca / sblocca l'IP di destinazione: della connessione selezionata se ha il focus il pannello connessioni, altrimenti dell'alert selezionato |
| `s` / `r` | `SIGSTOP` / `SIGCONT` sul processo |
| `k` | `SIGKILL` (con conferma) |
| `c` | Svuota la lista alert |
| `tab` / `shift+tab` | Cambia pannello |
| `q` | Esci |

### Diagnostica

`sudo uv run safemaxxing doctor` controlla:

- macOS e la sua versione;
- se gira come root;
- i binari `log`, `pfctl` e `lsof`;
- lo stato di pf (`pfctl -s info` → Enabled/Disabled);
- la presenza di `anchor "com.apple/*"` nel ruleset principale;
- lo stato dell'anchor `com.apple/safemaxxing`;
- la visibilità dei socket di altri utenti (via `lsof -FpL`);
- il Full Disk Access del terminale (lettura del `TCC.db` di sistema; per ora facoltativo);
- la latenza di uno snapshot dei socket rispetto a `--poll-ms`;
- la validità del predicato di `log stream`.

Senza root, i tre controlli su pf e lo snapshot dei socket risultano "needs root".

`sudo uv run safemaxxing sample --seconds 5 --out sample.jsonl` cattura log reali. Per ogni
sottosistema mostra:

- quante righe sono oscurate (`<private>` / `<mask.hash: …>`);
- quante vengono classificate, e con quale attribuzione (PID / bundle id);
- la sequenza delle attribuzioni dell'indicatore di Control Center;
- un esempio per sensore ed esempi di righe non riconosciute.

`--wide` cerca per parole chiave in tutti i sottosistemi e `--debug` usa `--level debug`.
Allegare l'output testuale a una issue è il modo più rapido per migliorare le euristiche. Il
file `--out` contiene invece il log di sistema grezzo: non pubblicarlo.

Se i campi sono oscurati, macOS consente di mostrarli installando un profilo di configurazione
con il payload `com.apple.system.logging` e `Enable-Private-Data = true`. Fallo solo su
macchine di test, perché espone dati sensibili nel log di sistema.

### Note sul firewall

I blocchi persistono dopo l'uscita da safemaxxing, fino a `safemaxxing flush`. **Non
sopravvivono al riavvio**: dopo un restart pf torna allo stato di boot e la tabella non
esiste più. Prima del primo blocco di ogni processo (cioè a ogni comando `block`, ma una
sola volta per sessione in `tui` / `watch`) safemaxxing:

1. rifiuta di procedere se il ruleset principale non valuta `anchor "com.apple/*"`, perché le
   regole dell'anchor sarebbero ignorate, e suggerisce `sudo pfctl -f /etc/pf.conf`;
2. se l'anchor non è ancora caricato, valida le regole con un dry-run
   (`pfctl -a com.apple/safemaxxing -n -f -`) prima di caricarle, ignorando i warning innocui
   di Darwin (ALTQ, avviso su `-f`);
3. abilita pf se è disattivato (`pfctl -E`, con fallback `pfctl -e`) e verifica con `-s info`;
4. dopo `-T add` elimina gli stati esistenti verso l'IP (`pfctl -k 0.0.0.0/0 -k <IP>`,
   `::/0` per IPv6), così smettono di funzionare anche i socket già aperti.

`flush` svuota la tabella, ma la regola dell'anchor resta caricata e pf resta attivo. Per
ispezionare lo stato:

```bash
sudo pfctl -a com.apple/safemaxxing -s rules
sudo pfctl -a com.apple/safemaxxing -t safemaxxing_block -T show
```

## Architettura

```
src/safemaxxing/
├── models.py        Event, SensorType, NetworkConnection, Finding, Alert, ActionResult (frozen)
├── sensors.py       log stream → JsonStreamDecoder → SensorEventParser/parse_entry → cooldown → Event
├── network.py       psutil / lsof → outbound_only → NetworkMonitor (+ HostnameResolver)
├── correlation.py   CorrelationEngine: buffer circolari, finestra temporale, severità
├── supervisor.py    unisce gli stream asincroni e alimenta l'engine
├── firewall.py      PfFirewall (pfctl) e ProcessController (segnali)
├── diagnostics.py   doctor (Check) e sample (summarize_sample)
├── tui/app.py       dashboard Textual
└── cli.py           entry point Typer
```

Tutti i componenti con side effect accettano dipendenze iniettabili: il comando `log`, lo
snapshot dei socket, il runner di `pfctl` e la funzione `kill`. Per questo la logica è
testabile anche su Linux (la CI gira su macOS).

## Limiti noti

- safemaxxing vede solo i socket *nuovi*. Un'app che riusa una connessione già aperta (i
  browser lo fanno di continuo) non produce un nuovo egress da correlare.
- Le risoluzioni DNS (porte 53, 853, 5353) sono escluse per default, perché precedono la
  connessione vera. `--include-dns` le include.
- Per default gli eventi dei binari Apple protetti da SIP (`/System`, `/usr` tranne
  `/usr/local`, `/bin`, `/sbin`) sono nascosti e non vengono correlati, e lo stesso vale per i
  loro socket. Servizi come `cloudd` o `apsd` usano la rete di continuo e genererebbero falsi
  positivi. I socket restano comunque visibili nel pannello connessioni. Usa
  `--include-system` per includerli. Eccezione: gli eventi dell'indicatore di Control Center
  per le app Apple oggi non sono marcati come di sistema e compaiono comunque
  ([TODO.md](TODO.md)).
- Molte app Apple (FaceTime, Messaggi) delegano la rete a daemon di sistema (`avconferenced`,
  `identityservicesd`). L'accesso al sensore e la connessione avvengono quindi in processi
  diversi e non producono alert. La correlazione è pensata per le app di terze parti che fanno
  rete da sé.
- Le euristiche per `cmio` / `coreaudio` / `locationd` dipendono dal formato dei messaggi di
  log, che Apple cambia tra una versione di macOS e l'altra.
  - Le attribuzioni dell'indicatore di Control Center sono la fonte più affidabile.
  - Le righe TCC richiedono filtri sui daemon broker e sui preflight.
  - Su macOS 27.0.1 sono stati osservati tutti e quattro gli indicatori: `cam:`, `mic:`, `loc:`
    e `scr:`. Uno screenshot con Cmd+Shift+5 viene attribuito a SystemUIServer
    (`scr:com.apple.systemuiserver`), non al tool che cattura. La registrazione video dello
    schermo e la
    condivisione via ScreenCaptureKit non sono ancora state verificate.
- Il reverse DNS gira in background su un pool dedicato (4 thread) e il polling non lo
  aspetta mai. Il nome host compare nel pannello connessioni appena risolto. Un alert invece
  mostra il nome solo se l'IP era già in cache; altrimenti mostra solo l'IP.
- Il polling dei socket (default 200 ms) può perdere le connessioni brevissime. Un backend
  basato su Network Extension / Endpoint Security risolverebbe il problema.
- **SNI**: oggi il nome host arriva dal reverse DNS. Estrarre lo SNI dal ClientHello richiede
  la cattura dei pacchetti (pcap/NE) ed è nella roadmap ([TODO.md](TODO.md)).
- I blocchi non sopravvivono al riavvio (vedi [Note sul firewall](#note-sul-firewall)).
- `SIGSTOP` su un'app GUI può lasciare finestre non responsive finché non si invia `SIGCONT`.

## Sviluppo

```bash
uv sync
uv run ruff format . && uv run ruff check .
uv run mypy
uv run pytest
```

Workflow, convenzioni e regole per i log di test: [CONTRIBUTING.md](CONTRIBUTING.md).

### Test live su Mac

`tests/live/` contiene test contro il kernel Darwin e il log unificato reali, saltati di
default. Aggiungono e rimuovono sempre un solo IP nella tabella `safemaxxing_block`: per
default `1.1.1.1`, configurabile con `SAFEMAXXING_LIVE_IP`. Caricano anche la regola
dell'anchor e abilitano pf, e le lasciano attive alla fine.

```bash
sudo SAFEMAXXING_LIVE=1 "$(which uv)" run pytest -m live -v -s
```

I test live verificano:

- `doctor` senza errori;
- il parsing pulito di anchor e tabella;
- il drop effettivo delle nuove connessioni e di quelle già aperte;
- il ripristino dopo l'unblock;
- un campionamento di 5 s di `log stream`, con report su redazione e parsing.

La durata del campionamento si cambia con `SAFEMAXXING_LIVE_SAMPLE_S`; le altre variabili
sono in [CONTRIBUTING.md](CONTRIBUTING.md).

Per una validazione completa con raccolta delle evidenze in `testlogs/` c'è
[`scripts/macos_validate.sh`](scripts/macos_validate.sh).

## Documentazione del progetto

| File | Contenuto |
|------|-----------|
| [CHANGELOG.md](CHANGELOG.md) | Modifiche visibili all'utente |
| [TODO.md](TODO.md) | Task aperti, in corso e completati (con commit) |
| [TESTLOG.md](TESTLOG.md) | Ogni sessione di test, con ambiente, comandi e risultati grezzi |
| [testlogs/](testlogs/) | Log grezzi di `scripts/macos_validate.sh` dal Mac |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Ciclo di sviluppo, test live, convenzioni |
| [SECURITY.md](SECURITY.md) | Segnalazione vulnerabilità, cosa safemaxxing modifica sul sistema |

## Licenza

[MIT](LICENSE)
