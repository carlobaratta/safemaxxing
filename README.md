# safemaxxing

**Privacy supervisor ed egress firewall headless per macOS, basato su correlazione di eventi.**

LuLu e Little Snitch ti chiedono *"questa app può connettersi a X?"*. safemaxxing risponde a
una domanda diversa: **"questa app ha appena acceso la fotocamera e, nei 500 ms successivi,
ha aperto un socket verso Internet?"**

Rileva la catena causa → effetto tipica dell'esfiltrazione:

```
 [Sensore]  kTCCServiceCamera  pid=4242 com.example.spy      t = 0 ms
     │
     ▼  finestra di correlazione (default 500 ms)
 [Egress]   tcp 10.0.0.5:51544 -> 203.0.113.9:443 pid=4242   t = 87 ms
     │
     ▼
 [Alert]    HIGH  com.example.spy used camera then connected to 203.0.113.9:443 after 87 ms
     │
     ├── b  → pfctl -a com.apple/safemaxxing -t safemaxxing_block -T add 203.0.113.9
     ├── s  → SIGSTOP 4242   (r → SIGCONT)
     └── k  → SIGKILL 4242
```

## Funzionalità

- **Sensori** — `log stream --style json` asincrono con predicati su `com.apple.TCC`,
  `com.apple.locationd`, `com.apple.coreaudio`, `com.apple.cmio`. Classifica Fotocamera,
  Microfono, Posizione, Screen Capture e qualunque altro servizio TCC, attribuendo l'accesso al
  PID / bundle id del *client* (non al daemon broker come `tccd` o `coreaudiod`).
- **Socket mapper** — polling della tabella socket via `psutil` (fallback `lsof -F`), solo
  connessioni *in uscita* (TCP `SYN_SENT`/`ESTABLISHED` non accettate su porte in ascolto, UDP
  connessi), risoluzione del bundle id dall'`Info.plist` dell'app e reverse DNS con cache.
- **Correlazione** — buffer circolari in memoria per eventi e connessioni, match per PID o
  bundle id (inclusi gli helper, es. `com.google.Chrome.helper`), finestra configurabile,
  tolleranza al clock skew e all'arrivo in ritardo delle righe di log, deduplica e cooldown
  degli alert. Severità aumentata se lo stesso attore usa più sensori.
- **Enforcement** — tabella pf `safemaxxing_block` dentro l'anchor `com.apple/safemaxxing`
  (già valutato dal `/etc/pf.conf` di sistema, quindi nessuna modifica alla configurazione) e
  controllo processi con `SIGSTOP` / `SIGCONT` / `SIGKILL`.
- **TUI Textual** — alert, connessioni attive e stream degli eventi sensore in tempo reale.
- **Headless** — `safemaxxing watch` con output JSON lines e azioni automatiche opzionali.

## Installazione

Requisiti: macOS 13+ (Apple Silicon o Intel), Python 3.12+, [`uv`](https://docs.astral.sh/uv/).

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
```

Root è necessario per: vedere i socket di altri utenti, leggere tutti i log TCC, usare `pfctl`
e inviare segnali a processi altrui. Senza root safemaxxing funziona in modalità degradata.

### Tasti della TUI

| Tasto | Azione |
|-------|--------|
| `b` / `u` | Blocca / sblocca l'IP di destinazione dell'alert o connessione selezionata |
| `s` / `r` | `SIGSTOP` / `SIGCONT` sul processo |
| `k` | `SIGKILL` (con conferma) |
| `c` | Svuota la lista alert |
| `tab` | Cambia pannello |
| `q` | Esci |

### Note sul firewall

I blocchi persistono dopo l'uscita da safemaxxing (fino a `safemaxxing flush` o al riavvio).
safemaxxing abilita pf con `pfctl -E` se necessario. Per ispezionare lo stato:

```bash
sudo pfctl -a com.apple/safemaxxing -s rules
sudo pfctl -a com.apple/safemaxxing -t safemaxxing_block -T show
```

## Architettura

```
src/safemaxxing/
├── models.py        Event, SensorType, NetworkConnection, Finding, Alert, ActionResult (frozen)
├── sensors.py       log stream → JsonStreamDecoder → parse_entry → Event
├── network.py       psutil / lsof → outbound_only → NetworkMonitor (+ HostnameResolver)
├── correlation.py   CorrelationEngine: buffer circolari, finestra temporale, severità
├── supervisor.py    unisce gli stream asincroni e alimenta l'engine
├── firewall.py      PfFirewall (pfctl) e ProcessController (segnali)
├── tui/app.py       dashboard Textual
└── cli.py           entry point Typer
```

Tutti i componenti con side effect accettano dipendenze iniettabili (comando `log`, snapshot
dei socket, runner di `pfctl`, funzione `kill`), quindi la logica è testabile anche su Linux.

## Limiti noti

- Le euristiche per `cmio` / `coreaudio` / `locationd` dipendono dal formato dei messaggi di
  log, che Apple cambia tra versioni di macOS. Le righe TCC (`kTCCService*`) sono le più stabili.
- Il polling dei socket (default 200 ms) può perdere connessioni brevissime; un backend basato
  su Network Extension / Endpoint Security è nella roadmap.
- **SNI**: oggi il nome host è ottenuto via reverse DNS. L'estrazione dello SNI dal ClientHello
  richiede cattura pacchetti (pcap/NE) ed è nella roadmap.
- `SIGSTOP` su app GUI può lasciare finestre non responsive finché non si invia `SIGCONT`.

## Sviluppo

```bash
uv sync
uv run ruff format . && uv run ruff check .
uv run mypy
uv run pytest
```

## Licenza

MIT
