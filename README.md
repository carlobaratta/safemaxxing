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

> **Stato:** alpha (0.2.1). Validato su macOS 27.0.1, Apple Silicon (vedi
> [TESTLOG.md](TESTLOG.md)); test unitari in CI su macOS arm64 e Intel. Gira come root e
> modifica pf: leggi [SECURITY.md](SECURITY.md) prima di usare le azioni automatiche.

## Indice

- [Funzionalità](#funzionalità)
- [Installazione](#installazione)
- [Utilizzo](#utilizzo)
  - [Menu bar](#menu-bar)
  - [Permessi TCC](#permessi-tcc)
  - [Diagnostica](#diagnostica)
  - [Demone `watch`](#demone-watch)
  - [Paranoia Mode](#paranoia-mode)
- [Privacy e dati](#privacy-e-dati)
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
  - Una richiesta TCC, anche per fotocamera, microfono o schermo, conta come `tcc` (severità
    `medium`): è un controllo dei permessi, e molte app lo fanno all'avvio (Spotify e Claude al
    login). Fotocamera, microfono e schermo vengono solo dall'uso reale: l'indicatore di
    Control Center e l'avvio dello stream cmio, 50-400 ms dopo la richiesta.
  - Attribuisce l'accesso al PID e al bundle id del *client*, non ai daemon broker come
    `tccd`, `coreaudiod` o `sandboxd`.
  - La fonte principale sono le attribuzioni dell'indicatore di privacy di Control Center
    (`Active activity attributions changed to ["cam:…", "mic:…", "loc:…"]`), verificate su
    macOS 27.
  - Screen Capture conta solo quando è il processo che cattura a registrare la propria
    richiesta: i preflight di WindowServer e `coreaudiod` per conto di altre app vengono
    scartati.
  - Le richieste ScreenCaptureKit passano da `replayd`: vengono attribuite al client che
    `tccd` indica nell'audit token del soggetto (`REQUEST_MSG`), per esempio Brave che
    condivide una finestra in Meet, non a `replayd`.
  - Sono scartati anche i controlli `com.apple.private.tcc.manager` che i daemon fanno per
    conto di altri.
  - Sono scartati anche i *preflight* di `coreaudiod`, cioè le verifiche fatte quando un'app
    apre l'audio senza usare il microfono. Solo il `REQUEST_MSG` di `tccd` dice
    `preflight=true`, ma tutte le righe della stessa richiesta hanno lo stesso
    `activityIdentifier`, quindi viene scartata la richiesta intera.
  - Un'attribuzione dell'indicatore che si spegne e si riaccende entro 2 s conta come un solo
    uso. Durante una condivisione di Brave l'indicatore lampeggia circa una volta al secondo.
  - Le righe `CMIODeviceStartStream backtrace N` di cmio sono lo stack dell'avvio appena
    loggato, non nuovi avvii della fotocamera.
- **Socket mapper**: polling della tabella socket via `psutil`, con fallback `lsof -F`.
  - Tiene solo le connessioni *in uscita*: TCP `SYN_SENT`/`ESTABLISHED` non accettate su porte
    in ascolto, e UDP connessi.
  - Ricava il bundle id dall'`Info.plist` dell'app, o della system extension per i binari
    in `/Library/SystemExtensions` (es. quella di rete di Avast).
  - Fa il reverse DNS in background, con cache.
  - Risale la catena dei processi (antenati e *responsible pid*): un socket aperto da un
    helper (`curl`, un updater) o da un servizio XPC viene attribuito all'app che ne è
    responsabile.
- **Flussi UDP via pktap** (opzionale, `--udp-flows`, serve root): un `tcpdump -k` sempre
  attivo sull'interfaccia pktap, solo UDP in uscita e senza porte DNS.
  - Il kernel etichetta ogni pacchetto con il pid del processo e la direzione. Il primo
    pacchetto in uscita di un flusso diventa una connessione con stato `PKTAP`.
  - Così si vedono le destinazioni dei socket UDP mai `connect()`-ati, come i media di una
    call Meet in Brave.
  - Scarta il traffico link-local, multicast e broadcast (anche verso l'indirizzo di broadcast
    della sottorete di ogni interfaccia), il kernel e i binari SIP (salvo
    `--include-system`). I flussi già aperti all'avvio non contano come nuovi.
  - Se tcpdump si ferma viene riavviato, fino a 5 volte di fila.
  - Durante una call Meet costa circa lo 0,5% di un core.
  - `--tcp-flows` cattura anche i SYN TCP in uscita (un socket aperto e chiuso tra due
    polling); `--throughput` segnala un flusso già aperto quando il suo traffico in uscita
    sale di colpo rispetto alla sua media.
- **Correlazione**: buffer circolari in memoria per eventi e connessioni.
  - Fa il match per PID o per bundle id, inclusi gli helper (es. `com.google.Chrome.helper`).
  - La finestra è configurabile e tollera clock skew e righe di log arrivate in ritardo.
    Con `--decay-window-ms` una connessione oltre la finestra, ma entro quella di decadimento,
    viene ancora correlata, un livello di severità più in basso.
  - Produce un solo alert per connessione: se altri sensori la precedono, l'alert viene
    aggiornato con lo stesso id. Cooldown di 30 s per (pid, sensore, IP).
  - Le raffiche di righe di log di un accesso diventano un solo evento.
  - La severità base è `high` per fotocamera, microfono, schermo e posizione, `medium` per
    `tcc`. Sale di un livello, fino a `critical`, se più sensori diversi precedono la stessa
    connessione. Una richiesta `tcc` seguita dall'uso dello stesso sensore conta una volta sola.
- **Enforcement**: tabella pf `safemaxxing_block` dentro l'anchor `com.apple/safemaxxing`.
  L'anchor è già valutato dal `/etc/pf.conf` di sistema, quindi non serve modificare la
  configurazione. Controllo dei processi con `SIGSTOP` / `SIGCONT` / `SIGKILL`.
- **TUI Textual**: una dashboard a pannelli, con un solo colore d'accento e i colori di
  severità usati solo sugli alert. Niente lampeggia, nemmeno in Paranoia Mode.
  - **Temi**: scuro (default), alto contrasto e chiaro, con `--theme` o `T` mentre gira. Ogni
    coppia testo/sfondo rispetta il contrasto WCAG AA (4,5:1), il tema ad alto contrasto AAA
    (7:1); `NO_COLOR=1` rende monocromatico qualunque tema.
  - **Intestazione fissa**: profilo (Normal, Paranoia), numero di indirizzi bloccati, stato del
    demone `watch`, ora dell'ultimo evento e dell'ultimo controllo.
  - **Riga di stato** in alto: dice a parole se serve il tuo intervento. `● Watching` quando
    non c'è niente di aperto, `▲ N alerts to review` quando ci sono alert `high` o `critical`
    non ancora bloccati né sospesi, `■ Paranoia Mode` o `■ Stopped`. Non dice mai "sei al
    sicuro": safemaxxing osserva e può bloccare, non garantisce.
  - **Alerts**: il feed, con badge di severità (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), chip
    dei sensori (`CAM`, `MIC`, `LOC`, `SCR`, `TCC`) e badge di mitigazione (`BLK`, `STOP`).
    Si filtra con `/`. Vuoto, spiega cosa farebbe comparire un alert.
  - **Paranoia Mode**: stato della modalità, lease, concessioni e connessioni negate, e il
    pulsante per entrare o uscire.
  - **Protection**: stato di pf e dell'anchor, indirizzi bloccati, latenza del polling dei
    socket, cattura pktap e cache DNS. Rilegge pf ogni 5 s e dice a che ora l'ha fatto. pf spento senza blocchi è lo
    stato normale; diventa rosso solo se ci sono blocchi che non vengono applicati.
  - **Details**: pid, bundle id, percorso, firma del codice (`codesign`), destinazione,
    sensori ed eventi recenti della selezione.
  - **Timeline** al millisecondo di un alert (`Invio` o `spazio`): ogni evento sensore
    dell'app, poi l'egress.
  - Sotto il feed, a schede, lo stream degli eventi sensore, le connessioni attive e gli
    indirizzi bloccati in pf (scheda Blocked, da cui `u` sblocca). In
    fondo, una barra di stato con CPU del processo, pacchetti e flussi UDP al secondo, cache
    DNS ed eventi al secondo.
  - Se il monitoraggio si ferma (manca root, il Full Disk Access o `tcpdump`), la riga di
    stato dice perché e come rimediare; un toast conferma ogni blocco, sblocco o sospensione.
- **Headless**: `safemaxxing watch` con output JSON lines e azioni automatiche opzionali.
- **Menu bar** (`safemaxxing menubar`, extra `menubar`): icona di stato, ultimi alert con
  blocco e freeze a un clic, modalità Auto-Block / Auto-Suspend, lista degli IP bloccati.
  Vedi [Menu bar](#menu-bar).
- **Audit dei permessi TCC** (`safemaxxing permissions`): quali app hanno già il permesso per
  fotocamera, microfono, registrazione schermo, monitoraggio input, accessibilità e accesso
  completo al disco, con i titolari ad alto rischio evidenziati. Vedi
  [Permessi TCC](#permessi-tcc).
- **Paranoia Mode** (tasto `P` nella TUI, serve root): default-deny in uscita, con eccezioni
  solo per le app in uso in quel momento, verificate dalla firma del codice. Vedi
  [Paranoia Mode](#paranoia-mode).
- **Report e pulizia**: `safemaxxing report` esporta lo stato della protezione in Markdown,
  JSON o testo (`--redact` per una issue pubblica); `sudo safemaxxing purge` toglie tutto
  quello che safemaxxing ha lasciato sul Mac. Vedi [Privacy e dati](#privacy-e-dati).

## Installazione

Requisiti: macOS (Apple Silicon o Intel), Python 3.12+, [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/carlobaratta/safemaxxing
cd safemaxxing
uv sync                      # oppure: uv sync --extra menubar, per `safemaxxing menubar`
sudo uv run safemaxxing doctor
```

> **Root e percorsi scrivibili.** `sudo uv run` esegue come root il codice del virtualenv,
> che è scrivibile dal tuo utente: va bene su una macchina tua per sviluppo e test, ma
> qualunque processo con il tuo utente potrebbe modificarlo. Vedi
> [SECURITY.md](SECURITY.md#running-as-root-pktap-and-sigstop).

**Release firmate** (dalla prima release taggata, vedi
[packaging/README.md](packaging/README.md)): ogni
[GitHub release](https://github.com/carlobaratta/safemaxxing/releases) allega, per arm64 e
x86_64, un `.pkg` firmato e notarizzato e un tarball.

- Il `.pkg` installa una copia di proprietà di root in `/usr/local/libexec/safemaxxing` e il
  link `/usr/local/bin/safemaxxing`: è il modo consigliato per usarlo come root.
- La formula Homebrew (`brew tap carlobaratta/tap && brew install safemaxxing`) installa il
  tarball nel prefisso di Homebrew, che è scrivibile dal tuo utente. Usala solo per i comandi
  senza root (`doctor`, `permissions`, `version`), mai con `sudo` o `sudo brew services`.
- Il binario standalone include rumps, quindi `menubar` funziona anche dal `.pkg`.

## Utilizzo

```bash
sudo uv run safemaxxing tui                       # dashboard interattiva
sudo uv run safemaxxing tui --window-ms 800 --ignore com.apple.FaceTime
sudo uv run safemaxxing tui --paranoia-profile max  # Paranoia Mode (P) col profilo più restrittivo
sudo uv run safemaxxing tui --theme high-contrast   # temi: dark, high-contrast, light

sudo uv run safemaxxing watch --json              # headless, JSON lines su stdout
sudo uv run safemaxxing watch --auto-block --min-severity high

sudo uv run safemaxxing block 203.0.113.9
sudo uv run safemaxxing blocked
sudo uv run safemaxxing unblock 203.0.113.9
sudo uv run safemaxxing flush

sudo uv run safemaxxing boot install              # riapplica i blocchi a ogni avvio
uv run safemaxxing boot status
sudo uv run safemaxxing boot uninstall

sudo safemaxxing daemon install --auto-block      # watch in background (solo dal .pkg)
safemaxxing daemon status
sudo safemaxxing daemon uninstall

sudo uv run safemaxxing paranoia install          # watchdog della Paranoia Mode (tasto P)
sudo uv run safemaxxing paranoia blocklist        # scarica la blocklist DNS del sinkhole
sudo uv run safemaxxing paranoia uninstall

sudo uv run safemaxxing freeze 4242               # SIGSTOP (chiede conferma per i processi di sistema)
sudo uv run safemaxxing thaw 4242                 # SIGCONT
sudo uv run safemaxxing kill 4242                 # SIGKILL (idem; --yes salta la domanda)

sudo uv run safemaxxing menubar                   # icona nella barra dei menu (extra menubar)
sudo uv run safemaxxing permissions               # chi ha già i permessi TCC sensibili

uv run safemaxxing report --redact               # stato della protezione, da allegare a una issue
sudo uv run safemaxxing purge --dry-run           # cosa toglierebbe purge, senza toccare niente
sudo uv run safemaxxing purge                     # toglie job, regole pf, stato e log (chiede conferma)

uv run safemaxxing version
```

Root serve per vedere i socket di altri utenti, leggere tutti i log TCC, usare `pfctl` e
inviare segnali a processi altrui. Senza root safemaxxing funziona in modalità degradata.
`uv run safemaxxing <comando> --help` mostra tutte le opzioni.

### Opzioni di `tui` e `watch`

| Opzione | Default | Effetto |
|---------|---------|---------|
| `--window-ms N` | `2000` | Finestra di correlazione sensore → egress |
| `--decay-window-ms N` | `0` | Finestra di decadimento: correla ancora una connessione fino a N ms dopo l'accesso, con confidenza decrescente e un livello di severità in meno. `0` la disattiva |
| `--poll-ms N` | `200` | Intervallo di polling della tabella socket (min 20) |
| `--ignore ID` | — | Bundle id o nome processo da ignorare (match esatto, ripetibile). Vale solo se la firma del processo lo conferma: identificatore di firma uguale al bundle id (o un suo helper), firmato da Apple o da un Team ID; un nome processo vale solo per i binari Apple. Per le app di terze parti usa il bundle id |
| `--include-system` | off | Mostra gli eventi dei binari di sistema e correla anche i loro socket |
| `--include-dns` | off | Alert anche sulle risoluzioni DNS (porte 53/853/5353) |
| `--include-loopback` | off | Traccia anche `127.0.0.1` / `::1` |
| `--no-dns` | off | Disattiva il reverse DNS |
| `--udp-flows` | off | Cattura anche l'UDP in uscita con pktap (`tcpdump`, serve root): trova la destinazione dei socket UDP non connessi |
| `--tcp-flows` | off | Cattura anche i SYN TCP in uscita con pktap (serve root): trova i socket aperti e chiusi tra due polling |
| `--throughput` | off | Segnala una connessione già aperta quando il suo traffico in uscita ha un picco (pktap, serve root). Copre il TCP solo con `--tcp-flows`, altrimenti i flussi UDP |

Solo per `tui`:

| Opzione | Default | Effetto |
|---------|---------|---------|
| `--theme T` | `dark` | Tema dei colori: `dark`, `high-contrast` o `light` (`T` li alterna mentre gira). `NO_COLOR=1` li rende monocromatici |
| `--paranoia-profile P` | `standard` | Cosa rifiuta la Paranoia Mode (tasto `P`). `max` chiede conferma prima di partire e attiva ogni rifiuto: verifica del codice `STRICT` (rifiuta `disable-library-validation`, quindi le chiamate da Brave non partono), nessuna rete all'app in primo piano senza un lease manuale, revoca della concessione quando lo SNI è in blocklist, TCP 443 solo verso IP nominati da una risposta DNS. Resta fail-open (il watchdog ripristina v0.2) e non protegge da codice con root o da un kernel compromesso |

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
| `↑` / `↓` | Seleziona un alert nel feed, o una riga nelle schede Connections e Blocked; il pannello Details mostra la selezione |
| `b` / `u` | Blocca / sblocca l'IP di destinazione della selezione (nella scheda Blocked, `u` sblocca la riga). Un toast conferma l'esito |
| `s` / `r` | Sospende / riprende il processo (`SIGSTOP` / `SIGCONT`). Per un processo di sistema macOS (WindowServer, loginwindow, …) chiede prima conferma |
| `k` | `SIGKILL`, con conferma: `y` o il pulsante Kill process. Il focus parte su Cancel, quindi `Invio` da solo non uccide niente |
| `Invio` / `spazio` | Timeline al millisecondo della selezione |
| `y` | Copia un valore della selezione: PID, nome, percorso, bundle id, IP, hostname, la regola pf o il comando `pfctl` (con `1`-`9` o le frecce) |
| `/` | Filtra feed, connessioni, eventi sensore e indirizzi bloccati per nome processo, bundle id, pid, IP, hostname, severità o sensore; `Invio` tiene il filtro, `esc` lo toglie |
| `t` | Torna alla prima riga della tabella col focus, o all'inizio del log eventi |
| `c` | Svuota il feed (il log eventi e pf non cambiano) |
| `P` | Entra in [Paranoia Mode](#paranoia-mode) (col profilo `max` chiede conferma); premuto di nuovo, chiede conferma ed esce |
| `g` | Dà (o toglie) un lease manuale all'app della connessione selezionata (Paranoia Mode) |
| `T` | Cambia tema: scuro → alto contrasto → chiaro |
| `?` | Aiuto: tutti i tasti, le domande frequenti e come segnalare un bug |
| `tab` / `shift+tab` | Cambia pannello; il pannello col focus ha il bordo evidenziato |
| `q` | Esci |

Le azioni agiscono sempre su quello che mostra il pannello Details. `k` resta `SIGKILL`,
quindi la navigazione usa le frecce e non `j`/`k`. Il feed tiene gli ultimi 1000 alert, la
scheda Connections le 300 connessioni più recenti, il log eventi le ultime 2000 righe.

Tutto si usa da tastiera, anche le finestre di conferma, l'aiuto e la copia: `tab` sposta il
focus tra i pulsanti, `esc` chiude. Il footer mostra solo i tasti che hanno effetto sulla
selezione e sullo stato del momento (`u` solo se l'IP è bloccato, `r` solo se il processo è
sospeso, `g` solo in Paranoia Mode). Il layout si adatta alla larghezza del terminale: da 150
colonne in su i pannelli laterali hanno la larghezza piena, tra 110 e 150 si restringono, sotto
le 110 passano sotto il feed; l'intestazione si accorcia sotto le 130 colonne.

La copia usa la sequenza OSC 52 del terminale e, in più, `/usr/bin/pbcopy`: con `sudo`
`pbcopy` può non raggiungere gli appunti della tua sessione, quindi in Terminal.app o iTerm2
conviene abilitare l'accesso agli appunti da parte delle applicazioni nel terminale.

### Menu bar

`sudo uv run safemaxxing menubar` (dopo `uv sync --extra menubar`) mette safemaxxing nella barra
dei menu. Usa lo stesso supervisor di `tui` e `watch` e ne accetta le opzioni di base:
`--window-ms`, `--poll-ms`, `--ignore`, `--include-system`, `--include-dns`,
`--include-loopback`, `--no-dns` e `--udp-flows` (non `--decay-window-ms`, `--tcp-flows`,
`--throughput` né quelle solo di `watch`).

| Icona | Stato |
|-------|-------|
| ○ | Nessun sensore in uso |
| ● | Un sensore è stato usato negli ultimi 6 s |
| ⚠︎ | Un alert negli ultimi 20 s |
| ⊘ | Monitoraggio fermo: lo stream del supervisor è fallito o finito (motivo nel menu, notifica una volta) |

Il menu mostra:

- gli ultimi 5 alert, ciascuno con **Block IP** e **Freeze process**;
- **Auto-Block Mode** e **Auto-Suspend Mode**: agiscono sugli alert `high` e `critical`, al
  massimo una volta per alert (come `watch`);
- l'esito delle ultime 3 azioni, automatiche o manuali, con ✓ o ✗ e il motivo dell'errore;
- gli IP bloccati, ciascuno con **Unblock**, e **Flush All**. La lista si rilegge da pf ogni 5 s
  e dopo ogni azione;
- **Open TUI Dashboard**, che apre `safemaxxing tui` in una finestra di Terminal.

Il terminale da cui la lanci resta occupato (Ctrl-C la chiude) e mostra gli avvisi. Se macOS
non mostra l'icona, dopo 3 s lo dice lì: succede quando la barra dei menu è piena (su un Mac
con il notch le icone che non ci stanno accanto vengono nascoste, anche a seconda dei menu
dell'app in primo piano) o quando l'icona è disattivata in Impostazioni di Sistema > Barra dei
menu. Anche il motivo di un monitoraggio fermo viene stampato lì.

Un sensore conta come "in uso" per qualche secondo dopo l'ultimo accesso: il log riporta gli
accessi, non lo spegnimento. Gli accessi dei binari di sistema non accendono l'icona, salvo
`--include-system`; gli eventi dell'indicatore di Control Center contano sempre.

### Permessi TCC

`safemaxxing permissions` legge in sola lettura il `TCC.db` di sistema e quello dell'utente
(sotto `sudo`, quello di chi ha lanciato il comando) e mostra chi ha già un permesso per
fotocamera, microfono, registrazione schermo, monitoraggio input, accessibilità o accesso
completo al disco.

Un permesso è segnalato come ad alto rischio quando il client è un percorso e:

- è un interprete (`python3.12`, `bash`, `node`, `osascript`, …): il permesso vale per
  qualunque script gli si passi;
- sta fuori da `/Applications` e dai percorsi di sistema;
- non esiste più su disco;
- non è firmato, o è firmato ad-hoc (`--no-check-signatures` salta `codesign`).

Serve il Full Disk Access sul terminale; il database di sistema richiede anche root. Un client
indicato solo da bundle id non viene segnalato: vedi [Limiti noti](#limiti-noti).

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
- la validità del predicato di `log stream`;
- se `tcpdump` riesce a catturare su pktap (per `--udp-flows`; mai FAIL, solo WARN);
- i permessi TCC sensibili (vedi [Permessi TCC](#permessi-tcc)): WARN se c'è un titolare ad
  alto rischio o se un database non si legge, quindi senza root è sempre WARN;
- se `menubar` può partire, cioè se rumps è installato (mai FAIL, solo WARN).

Senza root, i tre controlli su pf e lo snapshot dei socket risultano "needs root", e quello
di pktap dice "needs root".

`sudo uv run safemaxxing sample --seconds 5 --out sample.jsonl` cattura log reali. Per ogni
sottosistema mostra:

- quante righe sono oscurate (`<private>` / `<mask.hash: …>`);
- quante vengono classificate, e con quale attribuzione (PID / bundle id);
- la sequenza delle attribuzioni dell'indicatore di Control Center;
- un esempio per sensore ed esempi di righe non riconosciute.

`--wide` cerca per parole chiave in tutti i sottosistemi e `--debug` usa `--level debug`.
Allegare l'output testuale a una issue è il modo più rapido per migliorare le euristiche. Il
file `--out` contiene invece il log di sistema grezzo: viene creato con permessi 0600, di tua
proprietà anche sotto `sudo`, e non va pubblicato.

`safemaxxing report` riassume lo stato della protezione: versione e macOS, pf e regole
dell'anchor, indirizzi bloccati (in pf e salvati), job launchd, Paranoia Mode, i controlli di
`doctor` e, da root, gli ultimi alert del demone. Formati `--format markdown` (default),
`json` o `text`; `--out FILE` lo scrive con permessi 0600; `--no-checks` salta `doctor`.
Per una issue pubblica usa `--redact`, che sostituisce gli indirizzi IP (lo stesso indirizzo
con lo stesso segnaposto), i percorsi della home, il tuo nome utente e il nome del Mac. Il
report non viene inviato da nessuna parte.

Se i campi sono oscurati, macOS consente di mostrarli installando un profilo di configurazione
con il payload `com.apple.system.logging` e `Enable-Private-Data = true`. Fallo solo su
macchine di test, perché espone dati sensibili nel log di sistema.

### Note sul firewall

I blocchi persistono dopo l'uscita da safemaxxing, fino a `safemaxxing flush`. Da soli **non
sopravvivono al riavvio**: dopo un restart pf torna allo stato di boot e la tabella non
esiste più. Per riaverli serve `sudo safemaxxing boot install` (vedi
[Blocchi dopo il riavvio](#blocchi-dopo-il-riavvio)).

Prima di ogni blocco safemaxxing:

1. rifiuta di procedere se il ruleset principale non valuta `anchor "com.apple/*"`, perché le
   regole dell'anchor sarebbero ignorate, e suggerisce `sudo pfctl -f /etc/pf.conf`;
2. se l'anchor non è ancora caricato (controllato una volta per sessione), valida le regole con un dry-run
   (`pfctl -a com.apple/safemaxxing -n -f -`) prima di caricarle, ignorando i warning innocui
   di Darwin (ALTQ, avviso su `-f`);
3. si assicura di avere un proprio riferimento a pf (`pfctl -E`, anche se pf è già attivo,
   con fallback `pfctl -e`) e verifica con `-s info`. Il token viene salvato in
   `/Library/Application Support/safemaxxing/pf-reference` (root, 0600);
4. dopo `-T add` elimina gli stati esistenti verso l'IP (`pfctl -k 0.0.0.0/0 -k <IP>`,
   `::/0` per IPv6), così smettono di funzionare anche i socket già aperti.

`flush` svuota la tabella e lascia caricata la regola dell'anchor (su una tabella vuota non
blocca nulla). Poi, se la Paranoia Mode non è attiva, rilascia il riferimento di safemaxxing
con `pfctl -X <token>`: pf si spegne solo se nessun altro programma (VPN, Condivisione
Internet) ne tiene uno. safemaxxing non esegue mai `pfctl -d`, che spegnerebbe pf per tutti.
Un token di prima di un riavvio o di un `pfctl -d` viene scartato senza rilasciarlo. Dettagli
in [SECURITY.md](SECURITY.md#pf-enabling-the-reference-token-and-flush). Per ispezionare lo
stato:

```bash
sudo pfctl -a com.apple/safemaxxing -s rules
sudo pfctl -a com.apple/safemaxxing -t safemaxxing_block -T show
```

### Blocchi dopo il riavvio

`block`, `unblock` e `flush` (anche dalla TUI e con `--auto-block`) salvano ogni modifica
riuscita in `/Library/Application Support/safemaxxing/blocklist`, un indirizzo per riga.
Il file è di root, mode 0644, e viene sostituito in modo atomico. Se il salvataggio fallisce
il blocco resta attivo nel kernel e il dettaglio dice `not saved for reboot: …`.

`sudo safemaxxing boot install` aggiunge al file gli IP già presenti nella tabella. Poi scrive
`/Library/LaunchDaemons/io.github.carlobaratta.safemaxxing.restore.plist` e lo carica con
`launchctl bootstrap system`. A ogni avvio il job esegue uno script `/bin/sh` che usa solo
`/sbin/pfctl` e strumenti di base del sistema, mai il codice Python di safemaxxing:

1. esce senza toccare pf se la lista è vuota o manca;
2. aspetta fino a 60 s che `com.apple.pfctl` carichi `/etc/pf.conf`, cioè che il ruleset
   principale contenga `anchor "com.apple/*"`;
3. carica la regola dell'anchor, aggiunge gli IP con `pfctl -T add -f <lista>`, abilita pf
   con `pfctl -E` e salva il token, così un `flush` successivo può rilasciarlo. Se trova un
   token salvato dopo l'ultimo avvio e pf è attivo, lo tiene e non ne prende un altro.

Il job scrive in `/var/log/safemaxxing-boot.log`. Anche il caricamento con `install` esegue
lo script una volta: aggiunge gli IP salvati alla tabella attiva e non ne toglie nessuno.
Prima di caricarlo, `install` prende il riferimento di safemaxxing a pf (se la lista non è
vuota), così lo script trova il token e non ne lascia uno orfano.
`boot status` mostra se il job è installato e caricato e confronta la lista salvata con la
tabella attiva. Con `boot uninstall` il job viene rimosso, mentre i blocchi attivi e la lista
restano.

### Demone `watch`

`sudo safemaxxing daemon install` tiene `watch --json` sempre attivo in background come
LaunchDaemon di root: parte al caricamento e a ogni avvio, e launchd lo riavvia se esce (al
massimo un riavvio ogni 10 s). Accetta le stesse opzioni di `watch` (`--ignore`,
`--udp-flows`, `--auto-block`, `--min-severity`, …); rilanciarlo con opzioni diverse sostituisce
quelle installate.

- Gli alert finiscono in `/var/log/safemaxxing-watch.log`, un oggetto JSON per riga; errori e
  traceback in `/var/log/safemaxxing-watch.err`. I log non vengono ruotati.
- `daemon status` mostra se il job è installato e in esecuzione (stato, pid, ultimo exit
  code), la riga di comando esatta e gli ultimi 5 alert.
- `daemon uninstall` ferma il demone e cancella il plist; log e blocchi fatti restano.
- Con `--auto-block` i blocchi vengono salvati come gli altri, quindi `boot install` li
  riapplica dopo il riavvio.
- Al login molte app chiedono a TCC microfono, fotocamera o schermo mentre si avviano: sono
  alert `medium` (`tcc`). Con `--auto-block` tieni `--min-severity` almeno a `high`, o il
  demone bloccherebbe i loro server a ogni accesso.

Il demone esegue safemaxxing stesso come root, quindi `install` rifiuta qualunque copia che un
utente non root possa modificare: funziona solo dal binario del `.pkg` in
`/usr/local/libexec/safemaxxing`, con ogni file e ogni cartella sopra di proprietà di root e
non scrivibili da gruppo o altri. Da un checkout dei sorgenti, da un virtualenv o da Homebrew
risponde `refusing to install the daemon` (vedi [SECURITY.md](SECURITY.md)). Per provarlo prima
di una release firmata, vedi [packaging/README.md](packaging/README.md).

### Paranoia Mode

La Paranoia Mode trasforma l'anchor `com.apple/safemaxxing` da lista di blocco in
**default-deny** del traffico in uscita. Passano solo:

- l'infrastruttura minima: DHCP, ICMPv6 di neighbour discovery, mDNS, NTP verso
  `time.apple.com`, APNs (porte 5223 e 2197 verso le reti Apple);
- il DNS, rediretto a un sinkhole locale che risponde NXDOMAIN ai domini della blocklist
  (anche via CNAME) e inoltra il resto ai resolver di sistema;
- le destinazioni che un'app **in uso** sta cercando di raggiungere.

Un'app è in uso quando tiene un *lease*: usa fotocamera, microfono o cattura dello schermo
secondo Control Center (30 s di grazia dopo la fine), è in primo piano (15 s) o l'hai
autorizzata a mano con `g` (revoca immediata). safemaxxing impara le sue destinazioni dai
pacchetti che il default-deny scarta su `pflog0` e, prima di concedere una tupla (protocollo,
IP, porta), verifica il processo: stato della firma dal kernel (`csops`), entitlement,
`codesign` sul codice in esecuzione e Team ID fissato al primo uso
(`/Library/Application Support/safemaxxing/pins.json`). Un processo che non è il titolare e
usa una destinazione concessa viene fermato con `SIGSTOP` (i daemon di sistema solo
segnalati). I resolver DoH/DoT pubblici non vengono mai concessi: né per IP, né per nome (il
sinkhole risponde NXDOMAIN a `*.cloudflare-dns.com`, `dns.google`, `dns.quad9.net`, agli
altri resolver che i browser offrono fra i preset DoH (NextDNS, OpenDNS, CleanBrowsing,
AdGuard, Mullvad, …) e al canary di Firefox `use-application-dns.net`).

```bash
sudo uv run safemaxxing paranoia install      # una volta: il watchdog (senza, P rifiuta)
sudo uv run safemaxxing paranoia blocklist    # facoltativo: blocklist DNS (StevenBlack hosts)
sudo uv run safemaxxing tui                   # poi P per entrare, P e conferma per uscire
```

- **Fail-open.** Un watchdog launchd di root, che esegue solo `/bin/sh` e `/sbin/pfctl`,
  ripristina le regole normali (tabella di blocco inclusa) se safemaxxing smette di battere
  il cuore per 5 s. Un crash non ti lascia offline, ma neanche protetto. Un riavvio esce
  sempre dalla Paranoia Mode.
- **Profili.** `--paranoia-profile standard` (default) o `max`: vedi
  [Opzioni](#opzioni-di-tui-e-watch).
- **Proxy trasparenti.** Un antivirus con protezione web (Avast Web Shield) o lo split
  tunneling di una VPN aprono loro le connessioni al posto delle app: pf vede l'estensione e
  non l'app in lease, e il traffico di quelle app viene negato. All'ingresso la TUI elenca le
  estensioni di rete attive e segnala la prima connessione negata di ogni app; disattiva il
  proxy mentre usi la Paranoia Mode.
- **Limiti.** pf non filtra per processo: una concessione vale per la destinazione, e un
  estraneo viene fermato dopo i primi pacchetti, non prima. Lo SNI del ClientHello è un audit
  a posteriori (`max` revoca la concessione). Non protegge da codice già root.

Design, misure e piano di validazione: [RFC 0001](docs/rfc/0001-paranoia-mode.md). La
Paranoia Mode non ha ancora una sessione di validazione come root in [TESTLOG.md](TESTLOG.md)
(spike S1-S6 del §10.2 dell'RFC): provala prima su una macchina di test.

## Privacy e dati

safemaxxing elabora tutto **in locale**: eventi dei sensori, connessioni, metadati dei
pacchetti e alert non lasciano il Mac. Non c'è telemetria, né analytics, crash reporting o
controllo degli aggiornamenti, né account, server o SDK di terze parti. L'unico traffico che
genera è il reverse DNS verso il resolver di sistema (`--no-dns` lo spegne), l'inoltro del
sinkhole DNS della Paranoia Mode ai resolver già configurati e il download della blocklist con
`paranoia blocklist`, solo quando lo lanci.

La TUI, la menu bar e `watch` tengono tutto in memoria. Scrivono su disco solo le funzioni che
attivi (blocchi persistenti, demone, Paranoia Mode) e gli export che chiedi; i log sono
leggibili solo da root (0600) e i job launchd girano con `Umask 077`.

`sudo safemaxxing purge` chiede conferma e poi toglie i job launchd, svuota e scarica tabelle e
regole dell'anchor pf, rilascia il riferimento a pf (mai `pfctl -d`) ed elimina stato e log
creati da safemaxxing. `--dry-run` mostra l'elenco senza toccare niente; si rifiuta mentre la
Paranoia Mode è attiva o gira un'altra istanza.

> **Attenzione.** safemaxxing gira come root e modifica pf, solo dentro il proprio anchor. Un
> blocco interrompe ogni connessione verso quell'indirizzo, per tutte le app. La Paranoia Mode
> è default-deny: chiamate, sincronizzazione, aggiornamenti e VPN possono smettere di
> funzionare finché è attiva. Usalo su Mac tuoi o che amministri: registrare quali app usa
> un'altra persona e dove si connettono può richiedere il suo consenso (nell'UE, GDPR e
> ePrivacy).

I dettagli (cosa legge, dove salva, con quali permessi) sono in [PRIVACY.md](PRIVACY.md);
le licenze delle dipendenze e dei font in
[docs/THIRD_PARTY_LICENSES.md](docs/THIRD_PARTY_LICENSES.md).

## Architettura

```
src/safemaxxing/
├── models.py        Event, SensorType, NetworkConnection, Finding, Alert, ActionResult (frozen)
├── sensors.py       log stream → JsonStreamDecoder → SensorEventParser/parse_entry → cooldown → Event
├── network.py       psutil / lsof → outbound_only → NetworkMonitor (+ HostnameResolver)
├── pktap.py         tcpdump -k → parse_pktap_line → PktapFlowTracker → PktapCapture (--udp-flows)
├── correlation.py   CorrelationEngine: buffer circolari, finestra temporale, severità
├── supervisor.py    unisce gli stream asincroni e alimenta l'engine
├── process_tree.py  catena dei processi responsabili di un socket (antenati, responsible pid)
├── throughput.py    picchi di traffico sui flussi già aperti (--throughput)
├── firewall.py      PfFirewall (pfctl), PfReference (token di pfctl -E), BlockList (lista
│                    salvata) e ProcessController (segnali)
├── boot.py          job launchd che riapplica la lista al boot (solo /bin/sh, pfctl e tool di base)
├── daemon.py        LaunchDaemon che tiene attivo `watch --json` (solo da un bundle di root)
├── diagnostics.py   doctor (Check) e sample (summarize_sample)
├── codesign.py      firma per l'inspector (codesign -dv) e stato del codice dal kernel (csops)
├── tcc_inspector.py audit in sola lettura dei TCC.db (permissions, check di doctor)
├── menubar.py       MenuModel (puro) e il runner rumps della barra dei menu
├── lockdown/        Paranoia Mode
│   ├── controller.py    LockdownController: ingresso, uscita, loop di apprendimento e verifica
│   ├── rules.py         testo delle regole pf del default-deny (puro)
│   ├── pf.py            carica ruleset e tabelle con pfctl
│   ├── leases.py        lease per app (sensore, primo piano, manuale) e periodi di grazia
│   ├── pflog.py         pacchetti scartati letti da pflog0
│   ├── dns.py           sinkhole DNS e blocklist
│   ├── sni.py           SNI dei ClientHello via pktap (audit)
│   └── watchdog.py      dead-man switch launchd (/bin/sh e pfctl)
├── tui/
│   ├── app.py           SafemaxxingApp: feed, tab eventi/connessioni, tema, timer, azioni
│   ├── panels.py        riga di stato, pannelli Paranoia Mode, Protection e Details (snapshot → Rich)
│   ├── screens.py       modali: conferma delle azioni irreversibili, timeline
│   ├── timeline.py      eventi dell'alert e passi della timeline (puro, senza Textual)
│   ├── badges.py        badge Rich per severità, sensori e mitigazioni
│   ├── palette.py       i colori della dashboard, in un posto solo
│   └── safemaxxing.tcss layout e variabili colore (allineate a palette.py)
└── cli.py           entry point Typer
packaging/           build PyInstaller, firma, .pkg (vedi packaging/README.md)
Formula/             formula Homebrew per il tap
```

Tutti i componenti con side effect accettano dipendenze iniettabili: il comando `log`, lo
snapshot dei socket, il runner di `pfctl` e la funzione `kill`. Per questo la logica è
testabile anche su Linux (la CI gira su macOS).

## Limiti noti

- Paranoia Mode blocca il DNS cifrato verso i resolver pubblici noti, per IP e per nome
  (`DOH_NAMES`), non verso un server DoH qualsiasi. Un browser con un lease, configurato a
  mano con un server DoH fuori da quella lista, risolve fuori dal sinkhole.
- safemaxxing vede solo i socket *nuovi*. Un'app che riusa una connessione già aperta (i
  browser lo fanno di continuo) non produce un nuovo egress da correlare, salvo un picco di
  traffico con `--throughput`.
- Le risoluzioni DNS (porte 53, 853, 5353) sono escluse per default, perché precedono la
  connessione vera. `--include-dns` le include.
- Per default gli eventi dei binari Apple protetti da SIP (`/System`, `/usr` tranne
  `/usr/local`, `/bin`, `/sbin`) sono nascosti e non vengono correlati, e lo stesso vale per i
  loro socket. Servizi come `cloudd` o `apsd` usano la rete di continuo e genererebbero falsi
  positivi. I socket restano comunque visibili nel pannello connessioni. Usa
  `--include-system` per includerli.
- Gli eventi dell'indicatore di Control Center portano solo un bundle id, che qualunque app può
  dichiarare.
  - Vengono nascosti dalla visualizzazione solo se tutti i processi in esecuzione che possono
    avere quel bundle id girano da un percorso protetto da SIP. Una copia di un'app Apple fuori
    da `/System` resta quindi visibile. Restano visibili anche un'app annidata che dichiara quel
    bundle id e un'app con l'`Info.plist` illeggibile o spostato.
  - Vengono comunque **sempre correlati**: i socket dell'app Apple vera sono di sistema e
    vengono già scartati. Un socket non di sistema con lo stesso bundle id produce quindi un
    alert.
  - Non vengono correlate le connessioni di un'app il cui bundle id, ricavato dal suo
    `Info.plist`, non coincide con quello dell'indicatore. È il caso di un'app annidata in
    un'altra, o di un `Info.plist` spostato dopo l'avvio. In quel caso l'evento resta visibile,
    ma non c'è alert.
- Molte app Apple (FaceTime, Messaggi) delegano la rete a daemon di sistema (`avconferenced`,
  `identityservicesd`). L'accesso al sensore e la connessione avvengono quindi in processi
  diversi. safemaxxing collega un socket all'app che ha avviato il suo processo o che macOS
  indica come responsabile, ma un daemon che non dichiara l'app per cui lavora resta
  scollegato e non produce alert. La correlazione è pensata per le app di terze parti che
  fanno rete da sé.
- Le euristiche per `cmio` / `coreaudio` / `locationd` dipendono dal formato dei messaggi di
  log, che Apple cambia tra una versione di macOS e l'altra.
  - Le attribuzioni dell'indicatore di Control Center sono la fonte più affidabile.
  - Le righe TCC richiedono filtri sui daemon broker e sui preflight.
  - Su macOS 27.0.1 sono stati osservati tutti e quattro gli indicatori: `cam:`, `mic:`, `loc:`
    e `scr:`. Uno screenshot con Cmd+Shift+5 viene attribuito a SystemUIServer
    (`scr:com.apple.systemuiserver`), non al tool che cattura. La registrazione video dello
    schermo con Cmd+Shift+5 è stata verificata il 2026-10-24, con la stessa attribuzione. La
    condivisione di una finestra da Meet in Brave (ScreenCaptureKit) è stata verificata il
    2026-10-26. La richiesta TCC viene attribuita a Brave. L'indicatore `scr:com.brave.Browser`
    però non resta acceso: si accende per circa 130 ms una volta al secondo.
- Il reverse DNS gira in background su un pool dedicato (4 thread) e il polling non lo
  aspetta mai. Il nome host compare nel pannello connessioni appena risolto. Un alert invece
  mostra il nome solo se l'IP era già in cache; altrimenti mostra solo l'IP.
- Il polling dei socket (default 200 ms) può perdere le connessioni brevissime: `--tcp-flows`
  le vede dal SYN. Un backend basato su Network Extension / Endpoint Security risolverebbe il
  problema anche senza pktap.
- **UDP non connesso**: i socket UDP mai `connect()`-ati non hanno un indirizzo remoto nella
  tabella dei socket, quindi vengono scartati. Sono quelli di WebRTC e QUIC, usati per
  esempio da una call Meet nel browser.
  - Senza `--udp-flows`, una call Meet in Brave non produce alert, perché il suo traffico non
    è visibile. Anche le connessioni TCP verso Google sono già aperte e vengono riusate.
  - Con `--udp-flows` la call produce l'alert: verificato il 2026-10-28 con camera e
    microfono di Brave, 188 ms prima del primo pacchetto UDP verso 74.125.250.248:3478, vedi
    [TESTLOG.md](TESTLOG.md).
  - Su una rete che blocca l'UDP, Meet ripiega su TCP dentro una connessione già aperta, e
    nessuna delle due sorgenti lo vede. È stato osservato su una rete, senza conferma.
  - I flussi pktap prendono il nome host dalla stessa cache del reverse DNS: il primo alert
    verso un IP nuovo mostra l'IP, come per la tabella dei socket.
  - Gli eventi sensore di Brave restano visibili e attribuiti correttamente (verificato il
    2026-10-26, vedi [TESTLOG.md](TESTLOG.md)).
- **SNI**: fuori dalla Paranoia Mode il nome host arriva dal reverse DNS. Lo SNI del
  ClientHello viene letto solo in Paranoia Mode, come audit dei flussi concessi
  (`lockdown/sni.py`); usarlo anche per dare un nome alle destinazioni nella TUI è nella
  roadmap ([TODO.md](TODO.md)).
- I blocchi sopravvivono al riavvio solo con `boot install` (vedi
  [Blocchi dopo il riavvio](#blocchi-dopo-il-riavvio)); verificato con un riavvio reale su
  macOS 27.0.1. Le modifiche fatte a mano con `pfctl` non finiscono nella lista salvata.
- `SIGSTOP` su un'app GUI può lasciare finestre non responsive finché non si invia `SIGCONT`.
- **Menu bar**: "Open TUI Dashboard" avvia un secondo supervisor (senza root) in Terminal,
  invece di collegarsi a quello della menu bar. La menu bar non è ancora stata provata su una
  sessione grafica reale.
- **Permessi TCC**: un'app terminale (Terminal, iTerm) con un permesso sensibile non viene
  segnalata, anche se il permesso vale per ogni script che vi gira: `doctor` stesso chiede il
  Full Disk Access per il terminale. Le euristiche guardano solo il percorso e la firma.

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
dell'anchor e abilitano pf, e le lasciano attive alla fine. I test sul riferimento di pf
prendono e rilasciano i propri token e lasciano pf com'era.

```bash
sudo SAFEMAXXING_LIVE=1 "$(which uv)" run pytest -m live -v -s
```

I test live verificano:

- `doctor` senza errori;
- il parsing pulito di anchor e tabella;
- il drop effettivo delle nuove connessioni e di quelle già aperte;
- il ripristino dopo l'unblock;
- che il kernel conti i token di `pfctl -E`, che `pfctl -X` lasci pf attivo finché un altro
  li tiene e rifiuti un token già usato, e che `PfReference` rilasci quello che prende;
- un campionamento di 5 s di `log stream`, con report su redazione e parsing.

La durata del campionamento si cambia con `SAFEMAXXING_LIVE_SAMPLE_S`; le altre variabili
sono in [CONTRIBUTING.md](CONTRIBUTING.md).

Per una validazione completa con raccolta delle evidenze in `testlogs/` c'è
[`scripts/macos_validate.sh`](scripts/macos_validate.sh).

## Documentazione del progetto

| File | Contenuto |
|------|-----------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architettura, diagrammi Mermaid (correlazione, iniezione delle dipendenze, severità) |
| [CHANGELOG.md](CHANGELOG.md) | Modifiche visibili all'utente |
| [TODO.md](TODO.md) | Task aperti, in corso e completati (con commit) |
| [TESTLOG.md](TESTLOG.md) | Ogni sessione di test, con ambiente, comandi e risultati grezzi |
| [testlogs/](testlogs/) | Log grezzi di `scripts/macos_validate.sh` dal Mac |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Ciclo di sviluppo, test live, convenzioni |
| [packaging/README.md](packaging/README.md) | Build standalone, firma, notarizzazione, release e Homebrew |
| [SECURITY.md](SECURITY.md) | Threat model, segnalazione vulnerabilità, pf/token, cosa modifica sul sistema, hardening |
| [PRIVACY.md](PRIVACY.md) | Cosa legge, salva e invia (niente telemetria), come togliere tutto, cosa può rompere |
| [docs/THIRD_PARTY_LICENSES.md](docs/THIRD_PARTY_LICENSES.md) | Licenze di dipendenze e font |
| [docs/rfc/0001-paranoia-mode.md](docs/rfc/0001-paranoia-mode.md) | Design della Paranoia Mode, misure e piano di validazione |

## Licenza

[MIT](LICENSE)
