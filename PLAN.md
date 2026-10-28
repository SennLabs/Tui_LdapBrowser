# LdapTui — Implementation Plan

A read-only, terminal-based LDAP/LDAPS directory browser for Linux, written in Rust with Ratatui. Active Directory is the primary target, and OpenLDAP and LLDAP must also work.

## 1. Goals and non-goals

**Goals**
- Connect to `ldap://` and `ldaps://` servers.
- Allow LDAPS with invalid or self-signed certificates, but only when a per-profile config flag enables it.
- Authenticate with a simple bind using credentials from a separate JSON secrets file. Prompt for missing credentials. Anonymous bind is also supported.
- Browse the Directory Information Tree (DIT) lazily, and view entries and their attributes.
- Follow DN-valued attributes (`member`, `memberOf`, `manager`, `seeAlso`, …) to jump between entries, with back/forward history.
- Search for users and groups, by DN, or with arbitrary attribute filters.

**Non-goals**
- No add, modify, delete or rename operations. The app never sends write operations.
- No StartTLS. Connections are plain `ldap://` or `ldaps://` only.
- No SASL, Kerberos or GSSAPI.
- No keyring or encrypted secrets storage. Plaintext `secrets.json` is the accepted design.
- Linux only. No Windows or macOS builds.
- No ad-hoc `--url` connections. Every connection comes from a config profile.
- No schema editing.

Export, mouse support, result sorting and column choice, bookmarks, entry diff and the membership tree were originally deferred and are now planned in section 5.6 and milestones 10–13.

## 2. Tech stack

| Concern | Crate | Notes |
|---|---|---|
| TUI | `ratatui` 0.30 | Widgets: `List`, `Table`, `Paragraph`, `Tabs`, `Block` |
| Terminal backend | `crossterm` 0.29 | Raw mode, alternate screen, key events, bracketed paste |
| LDAP client | `ldap3` 0.12 | Async (tokio); `LdapConnSettings::set_no_tls_verify`, `set_config` for a custom rustls config |
| TLS | `ldap3` feature `tls-rustls` | Pure Rust, no OpenSSL dependency |
| PEM loading | `rustls-pemfile` | Loads `ca_cert` into a rustls root store |
| Async runtime | `tokio` (rt-multi-thread, macros, sync, time) | LDAP calls run off the UI thread |
| Config / secrets | `serde`, `serde_json` | JSON for both files |
| Secret handling | `secrecy` | `SecretString`; zeroised on drop, `Debug` redacted |
| CLI args | `clap` (derive) | `--config`, `--secrets`, `--profile`, `--log-level`, `--check`, `--ascii`, `--no-mouse` |
| Paths | `directories` | XDG locations |
| Errors | `anyhow` (app), `thiserror` (modules) | |
| Logging | `tracing`, `tracing-subscriber`, `tracing-appender` | Logs to a file; the terminal belongs to the TUI |
| Clipboard | OSC 52 escape sequence (built in, no crate) | Works over SSH and in containers; best-effort, since some terminals disable it |

## 3. Configuration

### 3.1 `config.json` (non-secret, safe to commit)

Default location: `$XDG_CONFIG_HOME/ldaptui/config.json` (normally `~/.config/ldaptui/config.json`), overridable with `--config`.

```json
{
  "default_profile": "corp-ad",
  "profiles": {
    "corp-ad": {
      "host": "dc01.example.local",
      "port": 636,
      "scheme": "ldaps",
      "flavor": "ad",
      "base_dn": "DC=example,DC=local",
      "insecure_skip_verify": false,
      "ca_cert": "/etc/ssl/certs/example-root-ca.pem",
      "credentials": "corp-ad-reader",
      "timeout_secs": 10,
      "page_size": 500,
      "size_limit": 5000,
      "tree_child_limit": 1000,
      "show_all_naming_contexts": true
    },
    "lldap": {
      "host": "lldap.example.local",
      "port": 6360,
      "scheme": "ldaps",
      "flavor": "lldap",
      "base_dn": "dc=example,dc=local",
      "insecure_skip_verify": true,
      "credentials": "lldap-admin"
    },
    "openldap-dev": {
      "host": "localhost",
      "port": 389,
      "scheme": "ldap",
      "base_dn": "dc=example,dc=org",
      "credentials": null,
      "search": {
        "user_filter": "(&(objectClass=inetOrgPerson)(|(uid=*{q}*)(cn=*{q}*)(mail=*{q}*)))",
        "group_filter": "(&(objectClass=groupOfNames)(cn=*{q}*))"
      }
    }
  }
}
```

Field rules (all fields except `host` are optional):

| Field | Default | Meaning |
|---|---|---|
| `host` | required | Hostname or IP address. For LDAPS this must match the certificate (see 6.2). |
| `scheme` | `"ldaps"` | `"ldap"` or `"ldaps"`. |
| `port` | 389 or 636 by scheme | LLDAP uses 3890 and 6360, and the Global Catalog uses 3268 and 3269, so these must be set explicitly. |
| `flavor` | `"auto"` | `"ad"`, `"openldap"`, `"lldap"` or `"auto"`. Selects default filters and behaviour (section 10). |
| `base_dn` | discovered | When omitted, the RootDSE `defaultNamingContext` is used, falling back to the first `namingContexts` value. |
| `insecure_skip_verify` | `false` | Skips certificate validation. Only allowed with `ldaps`; with `ldap` it is a config error. Shows a red **INSECURE TLS** badge and logs a warning. |
| `ca_cert` | none | Path to a PEM CA bundle, added to the system roots. This is the preferred alternative to `insecure_skip_verify` for private CAs. |
| `credentials` | none | A key into `secrets.json`. `null` or missing means anonymous bind. |
| `timeout_secs` | 10 | Applies to both connecting and individual operations. |
| `page_size` | 500 | Page size for the Simple Paged Results control. |
| `size_limit` | 5000 | Maximum search results. Hitting it shows a "results truncated" warning. |
| `tree_child_limit` | 1000 | Maximum children loaded per tree node before "load more" (section 5.1). |
| `show_all_naming_contexts` | `true` | See section 5.1. |
| `search.user_filter` / `search.group_filter` | by flavor | Overrides the flavor's user/group search filter. `{q}` is replaced by the escaped search text. |
| `search.saved` | `[]` | Named raw filters offered in the search dialog's **Saved** tab (section 5.6.3). Each item: `{ "name", "filter", "base"?, "scope"? }`. Written by the app when you save a search. |
| `bookmarks` | `[]` | Bookmarks for the profile (section 5.6.4). Each item: `{ "name", "dn" }`. Written by the app when you add, rename or delete a bookmark. |
| `results.columns` | by flavor | Default result columns per result kind: `{ "users": [...], "groups": [...], "other": [...] }`, each a list of attribute names (section 5.6.7). |
| `results.sort` | `name` | Default sort column for results, with optional `":desc"` suffix. |
| `export.dir` | `~` | Default directory offered in the export dialog (section 5.6.1). |
| `mouse` (top level, not per profile) | `true` | Enables mouse capture (section 5.6.6). Capture is set up before a profile is chosen, so this lives next to `default_profile`. `--no-mouse` overrides it. |

Validation errors are reported before the TUI starts, naming the file, profile and field.

### 3.2 `secrets.json` (secret, never commit)

Default location: `$XDG_CONFIG_HOME/ldaptui/secrets.json`, overridable with `--secrets`.

```json
{
  "corp-ad-reader": {
    "bind_dn": "CN=svc-ldapread,OU=Service Accounts,DC=example,DC=local",
    "password": "s3cr3t"
  },
  "lldap-admin": {
    "bind_dn": "uid=admin,ou=people,dc=example,dc=local",
    "password_env": "LLDAP_ADMIN_PW"
  }
}
```

- `bind_dn` may also be an AD UPN (`user@example.local`) or `DOMAIN\user`. `username` is accepted as an alias.
- The password is resolved in this order: `password`, then the environment variable named by `password_env`, then an interactive prompt (section 3.3).
- At startup, warn if the file mode is not `0600` (group- or world-readable).
- Passwords are held in `SecretString` and are never logged, displayed or written anywhere.
- The repo ships `config.example.json` and `secrets.example.json`, and `.gitignore` includes `secrets.json`.

### 3.3 Credential prompt

- **Credential name not in `secrets.json`**: a login popup asks for both the bind DN/username and the password.
- **`bind_dn` present but no password**: a popup asks for the password only, with the bind DN shown read-only.
- Password input is masked. Paste is supported.
- Entered credentials are kept in memory for the session, so reconnects don't prompt again. They are never written to disk.
- If the bind fails with invalid credentials (result code 49), the prompt reappears showing "attempt N of 3". After 3 failures the app returns to the profile picker, to avoid locking out the AD account.
- For AD, the code-49 diagnostic message (`data 52e`, `data 775`, …) is decoded into "bad password", "account locked", "account disabled", "password expired" or "must change password".
- Choosing **anonymous** in the prompt (or `credentials: null`) skips binding.

## 4. Architecture

```
src/
  main.rs            CLI parsing, logging setup, terminal init/restore + panic hook, runs App
  config.rs          Config + Profile structs, defaults, validation
  secrets.rs         Secrets loading, permission check, password resolution
  ldap/
    mod.rs           LdapClient: connect, bind, rootDSE, search, read entry
    worker.rs        Tokio task that owns the connection; request/response channels
    model.rs         Entry, Attribute, SearchScope, DN helpers (parse, parent, RDN, escape)
    flavor.rs        Flavor detection and per-flavor defaults (filters, DN attributes, icons)
    filter.rs        Filter builders and RFC 4515 escaping
    range.rs         AD ranged attribute retrieval
    decode.rs        Value decoders (GUID, SID, FILETIME, UAC, groupType, generalized time)
  app/
    mod.rs           App state, event loop, action dispatch
    state.rs         Focus, Mode, TreeState, SearchState, History
    actions.rs       Action enum (keys → actions → state changes)
  ui/
    mod.rs           Layout and draw()
    tree.rs          Directory tree pane
    entry.rs         Entry/attributes pane
    value.rs         Full-value viewer popup
    search.rs        Search dialog and results pane
    profiles.rs      Profile picker
    login.rs         Credential prompt
    status.rs        Status bar and key-hint footer
    popup.rs         Help and error popups
  clipboard.rs       OSC 52 copy
```

### 4.1 Concurrency model

- The UI runs a synchronous draw/event loop on the main thread, polling crossterm events with a ~50 ms timeout.
- A tokio task (`ldap::worker`) owns the `ldap3::Ldap` handle. The UI sends `LdapRequest` messages on an `mpsc` channel and drains `LdapResponse` messages each tick.
- Every request carries an id. Stale responses (the user has moved on) are discarded.
- A spinner or "Loading…" marker appears on the node or pane that is waiting, so the UI never blocks.
- `Esc` during a long search sends an abandon (`Ldap::abandon`) for that operation.

### 4.2 LDAP operations (all read-only)

| Operation | LDAP call |
|---|---|
| Connect | `LdapConnAsync::with_settings(settings, url)` with `set_conn_timeout`, `set_no_tls_verify(insecure_skip_verify)`, and `set_config` with a rustls `ClientConfig` containing system roots plus `ca_cert` |
| Bind | `simple_bind(bind_dn, password)` then `.success()`; skipped for anonymous |
| RootDSE | Base search on `""` for `namingContexts`, `defaultNamingContext`, `configurationNamingContext`, `schemaNamingContext`, `supportedControl`, `supportedExtension`, `vendorName`, `vendorVersion`, `forestFunctionality`, `isGlobalCatalogReady`, `objectClass` |
| List children | `OneLevel` search, filter `(objectClass=*)`, attributes `objectClass` plus a display attribute. Paged when supported, capped at `tree_child_limit` |
| Read entry | `Base` search on the DN for `["*", "+"]`, followed by ranged retrieval for any `attr;range=…` results (section 10) |
| Search | User-chosen scope (subtree by default). Paged when supported, capped at `size_limit` |

- ldap3 places non-UTF-8 values in `bin_attrs` automatically. Known binary attributes (`objectGUID`, `objectSid`, `jpegPhoto`, `userCertificate`, `thumbnailPhoto`, …) are always treated as binary. Binary values are shown as hex, or decoded where a decoder exists.
- Referrals and continuation references are shown as non-followed leaf nodes (`↪ ldap://…`) and are never chased.
- Children are sorted client-side by RDN (case-insensitive), with containers and OUs first.

## 5. UI design

### 5.1 Main layout

```
┌ LdapTui ─ corp-ad ─ ldaps://dc01.example.local:636 ─ TLS ✓ ─ bound as svc-ldapread ─ AD ─────┐
│┌ Tree ─────────────────────────┐┌ Entry: CN=Jane Doe,OU=Staff,DC=example,DC=local ──────────┐│
││ ▾ DC=example,DC=local         ││ Attribute            Value                               ││
││   ▸ OU=Groups                 ││ objectClass          top, person, organizationalPerson…  ││
││   ▾ OU=Staff                  ││ cn                   Jane Doe                            ││
││     👤 CN=Jane Doe            ││ mail                 jane.doe@example.local              ││
││     👤 CN=John Smith          ││ memberOf          →  CN=Radiology,OU=Groups,DC=...       ││
││     … 1000 of 4213, + more    ││                   →  CN=VPN Users,OU=Groups,DC=...       ││
││   ▸ OU=Service Accounts       ││ userAccountControl   512 (NORMAL_ACCOUNT)                ││
││ ▸ CN=Configuration,DC=…       ││ pwdLastSet           133520123450000000 (2024-02-12 08:12)││
│└───────────────────────────────┘└──────────────────────────────────────────────────────────┘│
│ Tab focus  ↑↓ move  →/Enter expand  / search  g goto DN  f follow  b/F back/fwd  ? help  q quit│
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

- **Status bar**: profile, URL, TLS state, bound identity, detected flavor, last error or operation timing. TLS state is one of:
  - `TLS ✓` (green)
  - **INSECURE TLS** (red): certificate validation is skipped
  - **PLAIN** (yellow): plain LDAP. When combined with a non-anonymous bind, it reads **PLAIN — password sent unencrypted**.
- **Tree pane** (left, ~35%):
  - Loaded lazily and cached per node. `r` refreshes a node.
  - Icons and colours by objectClass: OU, container, user, computer, group, builtinDomain, GPO, referral, other. ASCII fallback icons are used with `--ascii` or when the locale isn't UTF-8.
  - **Tree roots**: the base DN is the first root and is expanded on connect. When `show_all_naming_contexts` is `true`, the other naming contexts from the RootDSE are listed below it, collapsed. For AD these are Configuration, Schema, DomainDnsZones and ForestDnsZones; for OpenLDAP, `cn=config` and `cn=Monitor` appear if readable. They cost nothing until expanded and can be hidden by setting the option to `false`. *(Default chosen because you weren't sure; it is easy to flip.)*
  - **Large containers**: at most `tree_child_limit` children are loaded. A `… N of M, + more` row loads the next batch. Pressing `:` in the tree filters the current node's children by RDN prefix, applied server-side as `(name=prefix*)` for AD or `(|(cn=prefix*)(ou=prefix*)(uid=prefix*))` for the others.
- **Entry pane** (right):
  - Attributes table: `objectClass` first, then alphabetical, then operational attributes when toggled with `o`.
  - Multi-valued attributes span rows, and long values are truncated with `…`.
  - DN-valued attributes are marked `→` and can be followed.
  - Decoded values show the raw value plus a readable form in parentheses.
- **Value viewer** (`v` or `Enter` on a non-DN value): a scrollable popup showing the full value with wrapping. Binary values are shown as a hex dump. Certificates show subject, issuer and validity if parsing is cheap (stretch goal).
- **Footer**: context-sensitive key hints.
- **Minimum terminal size**: 80×24. Below 100 columns, the tree and entry panes stack vertically. Below 80×24, a "terminal too small" message is shown.
- `NO_COLOR` is respected.

### 5.2 Screens and modes

1. **Profile picker**: shown at start unless `--profile` is given or there is only one profile. Lists each profile's name, scheme, host:port and flavor, with an insecure marker. Enter connects.
2. **Login prompt**: as described in section 3.3.
3. **Browse** (default): tree and entry panes.
4. **Search dialog** (`/`): a modal form:
   - Type tabs: **Users** | **Groups** | **DN** | **Attribute** | **Raw filter**
   - Input field(s); search base (defaults to the selected tree node, editable); scope (base/one/sub)
   - Results replace the tree pane as a "Results (N)" list with DN and summary columns. Selecting a result shows the entry. `Esc` returns to the tree.
5. **Go to DN** (`g`): type or paste a DN to jump to it. The tree expands the path to the entry, loading parents as needed.
6. **Value viewer**, **Help** (`?`), and **Error popup** (readable message, plus the underlying LDAP result code and diagnostic text).

All text inputs support bracketed paste, cursor movement, `Ctrl-U` (clear) and `Ctrl-W` (delete word).

### 5.3 Search semantics

All user input is escaped per RFC 4515, except in Raw filter mode and except for `*` in Attribute mode.

| Type | Behaviour |
|---|---|
| Users | The flavor's user filter (section 10), or `search.user_filter` |
| Groups | The flavor's group filter (section 10), or `search.group_filter` |
| DN | Base-scope read of the exact DN. If it doesn't exist, fall back to a subtree search on the RDN value |
| Attribute | `(attr=value)`. The attribute name is validated as a plain attribute descriptor. `*` wildcards are allowed in the value |
| Raw filter | Passed through as typed. Server-side syntax errors are shown in the error popup |

- Result summary column: `displayName` or `cn`, plus `mail` or `description`.
- Recent searches are kept in memory and can be recalled with ↑↓ in the input field.

### 5.4 Following trees of entries

- In the entry pane, `Enter` or `f` on a DN value navigates to that entry and reveals it in the tree.
- Browser-style history: `b`/`Backspace` goes back and `F` goes forward. `Backspace` only does this in browse mode, not in text inputs.
- **Members view** (`m` on a group): lists `member`, `uniqueMember` and `memberUid` values (with ranged retrieval on AD). Each value is resolved to a summary and can be followed.
- **MemberOf view** (`M` on a user or group): shows direct membership, with a toggle (`n`) for nested membership:
  - AD: uses `LDAP_MATCHING_RULE_IN_CHAIN` and includes the primary group (section 10).
  - OpenLDAP: uses `memberOf` when present, otherwise a reverse search; nested membership is resolved client-side with cycle detection and a depth limit of 10.
  - LLDAP: direct membership only.
- DN detection: the attribute is in the flavor's list of DN-syntax attributes, or the value parses as a DN ending in a known naming context.

### 5.5 Key bindings

| Key | Action |
|---|---|
| `↑↓` / `j k`, `PgUp/PgDn`, `Home/End` | Move selection |
| `→` / `l` / `Enter` | Tree: expand. Entry: follow DN or open value viewer |
| `←` / `h` | Collapse node / go to parent |
| `Tab` / `Shift-Tab` | Cycle focus between panes |
| `/` | Search dialog |
| `:` | Filter children of the current tree node |
| `g` | Go to DN |
| `f` | Follow selected DN value |
| `v` | View full value |
| `b` / `Backspace`, `F` | History back / forward |
| `m` / `M` | Members view / memberOf view |
| `r` | Refresh node or entry |
| `o` | Toggle operational attributes |
| `y` / `Y` | Copy DN / copy selected value (OSC 52) |
| `e` | Export (entry, results, tree children) |
| `:` (entry pane) | Filter attributes by name |
| `B` / `'` | Toggle bookmark / open bookmark list |
| `d` / `D` | Mark entry for comparison / diff against the marked entry |
| `s` / `S` / `c` | Results: cycle sort column / reverse order / choose columns |
| `t` | Members or memberOf view: toggle flat list and tree |
| `R` | Reconnect to the current profile |
| `P` | Switch profile (back to the picker) |
| `?` | Help |
| `q` / `Ctrl-C` | Quit |

### 5.6 Planned additions

These features extend the browser without adding any write operation. Everything here works on data that is already fetched, or uses the same read-only search and base-read calls as the rest of the app.

#### 5.6.1 Export

`e` opens the export dialog for whatever is in focus:

| Focus | Exported |
|---|---|
| Entry pane | The current entry (all loaded attributes; operational ones only if `o` is on) |
| Results pane (search) | Every hit, with the attributes currently selected as columns plus the DN |
| Results pane (members / memberOf) | Every row, with DN, name and summary; nested rows include their depth |
| Tree pane | The selected node's loaded children (DN and RDN only; nothing is fetched) |

- Formats: **LDIF** (RFC 2849; binary and non-safe values base64-encoded with `::`, lines folded at 76 columns), **JSON** (one object per entry, attributes as arrays, binary as `{"base64": ...}`), **CSV** (one row per entry, multi-valued attributes joined with `; `, RFC 4180 quoting). LDIF is only offered for whole entries, not for column-limited results.
- Dialog fields: format tabs, file path (pre-filled from `export.dir` and a name derived from the RDN or the search, with Tab path completion), and a *decoded values* toggle that writes readable forms (GUID strings, dates, flag names) instead of raw values for JSON and CSV.
- Secret attributes (the decoder's secret-attribute list: `unicodePwd`, `userPassword`, …, which the entry pane already masks) are always written as `<redacted>` in JSON and CSV, and as a `# attr: n value(s) redacted` comment in LDIF, where a value may not start with `<`. Overwriting an existing file asks for confirmation.
- Export is synchronous: everything exported is already in memory, and serialising a few thousand rows takes milliseconds. The status bar reports the row count and path.

#### 5.6.2 Attribute filter in the entry pane

`:` is context-sensitive: in the tree pane it filters children (section 5.1); in the entry pane it filters the attribute table.

- The filter is a case-insensitive substring match on the attribute name, applied client-side as you type. `Esc` clears it; the filter is kept while navigating between entries until cleared, so you can flip through users while watching `lastLogon*` only.
- When active, the pane title reads `Entry: <dn> · filter: <text> (n of m)`.
- `objectClass` stays pinned at the top only when it matches the filter.

#### 5.6.3 Search history and saved searches

- **History**: the in-memory recall from section 5.3 is persisted to `$XDG_STATE_HOME/ldaptui/history.json`, per profile, keeping the last 50 entries of each search type. `↑↓` in the input recall them, most recent first, prefix-filtered by what is already typed. `Ctrl-D` on a recalled item deletes it. History holds filters and search bases only, never results or credentials.
- **Saved searches**: a sixth tab, **Saved**, lists `search.saved` from the profile (section 3.1), plus `search.saved` at the top level of `config.json` for filters shared by all profiles. Each row shows name, filter and base. `Enter` runs it; `e` loads it into the Raw filter tab for editing before running; `d` deletes it; `r` renames it. Saved filters may use `{q}`; when present, the dialog asks for the text first.
- `Ctrl-S` in any search tab saves the current filter, base and scope: a small prompt asks for a name and whether to store it under the profile or at the top level, then the app writes `config.json` (section 5.6.9).

#### 5.6.4 Bookmarks

- `B` toggles a bookmark on the current DN (the selected tree node, result or open entry). The name defaults to the RDN value and can be edited inline.
- `'` opens the bookmark list: a popup with name and DN, sorted by name. `Enter` navigates (same path reveal as go-to-DN), `d` deletes, `e` renames.
- Bookmarks live in the profile's `bookmarks` array in `config.json` (section 3.1), so they can be committed and shared with the profile. Every change is written straight back (section 5.6.9). Bookmarked nodes show a `★` marker in the tree and in results (`*` with `--ascii`).
- A bookmark whose DN no longer exists is shown dimmed with "(not found)" after a failed navigation; it is not removed automatically.

#### 5.6.5 Entry diff

- `d` marks the current entry for comparison. The status bar shows `compare: <rdn>` until cleared with `d` again on the marked entry; `d` on a different entry moves the mark. Closing the diff view keeps the mark, so one entry can be compared against several others in turn.
- `D` on another entry opens the **Diff** screen: a two-column table, left the marked entry and right the current one, headed by both DNs. Rows are attributes present in either entry, sorted as in the entry pane.
- Row states: *equal* (dimmed), *differs* (both values shown, differing values highlighted), *only left*, *only right*. Multi-valued attributes are compared as sets, with values ordered so that shared values line up first.
- `a` toggles between differences only (default) and all attributes. `o` includes operational attributes. `:` applies the attribute filter from 5.6.2 (the entry pane's current filter is carried over). `i` expands the identity group. `Tab` or `←`/`→` switches which side `f`, `y` and `Y` act on; `f` closes the diff and navigates. `Esc` closes the view.
- Attributes that are expected to differ (`objectGUID`, `objectSid`, `distinguishedName`, `name`, `cn`, `uSNChanged`, `whenCreated`, `whenChanged`, `dSCorePropagationData`) are grouped under a collapsible "identity" heading so that real differences stand out. The list is per flavor and can be extended in config later.
- Diff is purely client-side: both entries are already in the cache. `r` refreshes both.

#### 5.6.6 Mouse support

Enabled by default via crossterm mouse capture; disabled with `--no-mouse` or a top-level `"mouse": false`, and the help screen notes that terminal text selection needs `Shift` while capture is on.

| Action | Effect |
|---|---|
| Click in a pane | Focuses it and selects the row under the pointer |
| Click on a tree node's `▸`/`▾` | Expands or collapses without changing the entry pane |
| Double-click | Tree: expand or collapse. Results or members: open the entry. Entry pane: follow a DN or open the value viewer, like `Enter` |
| Scroll wheel | Scrolls the focused pane, or the pane under the pointer, 3 rows per notch |
| Click a results column header | Sorts by that column; click again reverses (section 5.6.7) |
| Click a tab in the search dialog, export dialog or help | Switches tab |
| Click a button-like footer hint | Triggers that key |
| Right-click | Context menu for the row: follow, copy DN, copy value, members, memberOf, bookmark, mark for diff, export |

Hit-testing uses the `Rect`s recorded during the last draw; no widget keeps its own geometry. Drag selection is not implemented.

#### 5.6.7 Result sorting and column choice

- Results are sorted client-side. `s` cycles the sort column through the visible columns, `S` reverses the order, and clicking a header does the same. The sorted column shows `▲`/`▼` in its header. The default comes from `results.sort`.
- Sorting is type-aware: decoded FILETIME and generalized-time attributes sort chronologically, numeric attributes numerically, everything else case-insensitively with "never" and empty values last.
- `c` opens the **Columns** picker: a checklist of candidate attributes (the flavor's summary attributes, the result kind's defaults, plus any attribute typed into a free-text row), reordered with `J`/`K`. Columns apply to the current results and are remembered per result kind for the session; the per-profile defaults live in `results.columns` (section 3.1).
- Column attributes are requested in the search itself. When the picker adds an attribute that the current results did not request, the search is re-run with the same filter and the extended attribute list, with a status-bar note. Removing a column never re-runs.
- Flavor defaults: AD users `sAMAccountName, displayName, mail, userAccountControl, lastLogonTimestamp`; AD groups `cn, groupType, description, member (count)`; OpenLDAP users `uid, cn, mail`; groups `cn, description`; LLDAP users `uid, displayName, mail`. `member (count)` is a virtual column computed from the returned values, honouring ranged retrieval.
- Too-narrow terminals drop columns from the right, keeping the name column; the footer shows how many are hidden.

#### 5.6.8 Group membership tree

`t` in the members or memberOf view toggles between the flat list and a **tree**.

- **MemberOf tree**: the root is the entry; its children are the groups it is a direct member of (including the AD primary group); each group expands lazily to the groups *it* belongs to. Expanding a node issues one base read of that group (`memberOf` on AD and LLDAP; the reverse search from section 5.4 on OpenLDAP without the overlay).
- **Members tree**: the root is the group; children are its direct members with their icons; member groups expand to their own members. Ranged retrieval applies at every level.
- A group that already appears on the path from the root is shown with `↻` and cannot be expanded, which handles cycles. Depth is limited to 10, matching the client-side nesting limit. A group that appears elsewhere in the tree is shown normally (the same group can be reached by several paths, and showing each path is the point).
- Each node shows the name and a dimmed DN; `Enter`/`f` navigates to it, `m`/`M` opens its own view, `y` copies its DN.
- The nested flag `n` is ignored in tree mode (the tree *is* the nested view); in flat mode it keeps its meaning. `e` exports the tree as indented CSV or JSON (section 5.6.1).
- Flat nested membership on AD still uses `LDAP_MATCHING_RULE_IN_CHAIN` because it is one query; the tree view is for understanding *why* a membership exists.

#### 5.6.9 Writing `config.json`

Saving a search or changing a bookmark updates the config file the app was started with (`--config` or the default path).

- The file is re-read immediately before writing, so edits made outside the app since startup are not lost. Only the `search.saved` and `bookmarks` arrays are changed, and for those the app's in-memory lists win; every other field is passed through as parsed. Key order is preserved (`serde_json` with `preserve_order`) and the output is pretty-printed with two-space indentation, which is the format of the example file.
- Writes are atomic: a temp file in the same directory, `fsync`, then `rename`. The original file's permission bits are copied to the new file.
- If the file cannot be written (read-only mount, permissions), the change is kept in memory for the session and the status bar reports the error; the help screen shows the path so it can be fixed by hand.
- `secrets.json` is never written.

## 6. Error handling and security

### 6.1 General
- A panic hook restores the terminal (leaves raw mode and the alternate screen) before printing the panic.
- Connection loss is detected on the next request. The status bar shows "Disconnected", and `R` reconnects using the cached credentials while keeping the tree state.
- Size limit or time limit exceeded (result codes 4 and 3) shows partial results with a warning.
- Errors map to plain-English messages with the LDAP result code and diagnostic text underneath.

### 6.2 TLS and transport
- **Certificate name mismatch**: connecting by IP address or short hostname to a DC whose certificate names its FQDN fails validation. The error popup detects this case and says "certificate is for X, you connected to Y; use the FQDN in `host`", rather than only suggesting `insecure_skip_verify`.
- **Untrusted CA**: the error suggests `ca_cert` first and `insecure_skip_verify` second.
- **AD over plain LDAP**: hardened domain controllers reject simple binds on `ldap://` with `strongerAuthRequired` (result code 8). The error popup explains this and recommends switching the profile to LDAPS on port 636. The README states that **AD should be used over LDAPS**.
- Any non-anonymous bind over plain `ldap://` logs a warning and shows the yellow PLAIN badge.

### 6.3 Secrets and logging
- Secrets are never logged. `SecretString` redacts itself in `Debug` output, and bind requests are logged without the password.
- Log file: `$XDG_STATE_HOME/ldaptui/ldaptui.log` (normally `~/.local/state/ldaptui/ldaptui.log`), rotated daily, keeping 7 files. The level is `info` by default and can be changed with `--log-level` or `RUST_LOG`.

## 7. Testing (no Docker)

Docker is not used. Test servers run as **native local processes** inside the devcontainer.

- **Unit tests**: config validation, secrets resolution, filter building and escaping, DN parsing, flavor detection from recorded RootDSE fixtures, ranged-attribute merging, value decoders (SID, GUID, FILETIME, UAC, groupType, AD bind-error codes).
- **UI tests**: render into ratatui's `TestBackend` and assert on key screens: layout, TLS badges, entry table, login prompt, and narrow layout.
- **Integration tests** (`#[ignore]`, run with `cargo test -- --ignored`):
  - **OpenLDAP**: install `slapd` and `ldap-utils` via apt (added to the devcontainer's setup). `scripts/test-slapd.sh` starts a throwaway `slapd` under `target/test-ldap/` with a generated config, on unprivileged ports (e.g. 10389 and 10636), with a self-signed CA and certificate generated by `openssl`. It loads an LDIF of OUs, users and nested groups, with the `memberof` overlay enabled.
  - **LLDAP**: `scripts/test-lldap.sh` downloads a pinned LLDAP release binary into `target/test-ldap/` and runs it with a temp SQLite database, TLS enabled using the same test CA, and seeds users and groups through its CLI or GraphQL API.
  - **Active Directory**: AD can't run locally. AD behaviour is covered by unit tests on recorded fixtures, plus an optional test suite driven by env vars (`LDAPTUI_AD_HOST`, `LDAPTUI_AD_BIND_DN`, `LDAPTUI_AD_PASSWORD`, …) that runs against a real DC when those are set.
  - Cases covered:
    - plain LDAP: anonymous and authenticated bind
    - LDAPS: `insecure_skip_verify: true` succeeds; `false` with an untrusted CA fails with a clear error; `ca_cert` set to the test CA succeeds; connecting by IP gives the name-mismatch error
    - credentials: bad password triggers the re-prompt path
    - browsing and searching: paged and unpaged listing, `tree_child_limit` with "load more", every search type, members/memberOf views
    - membership tree: nested groups expand level by level, a cycle in the seed data (group A ∈ B ∈ A) renders `↻` and stops, depth limit honoured
    - column choice: adding a column not in the original request re-runs the search and the new values appear
- **Unit tests for section 5.6**: LDIF folding and base64 rules, CSV quoting, JSON binary encoding, redaction of secret attributes on export; attribute filter matching; history persistence round-trip and the 50-entry cap; config round-trip for saved searches and bookmarks (other fields and key order preserved, permissions copied, external edits picked up); diff set comparison for multi-valued attributes and the identity-attribute grouping; type-aware sort comparators (FILETIME, generalized time, numeric, "never" last); mouse hit-testing against recorded `Rect`s; membership-tree cycle detection.
- **UI tests for section 5.6**: export dialog, diff screen with differences-only and all-attributes modes, bookmark markers in the tree, sort indicators in result headers, the membership tree with a cycle marker.
- **CI**: `cargo fmt --check`, `cargo clippy -- -D warnings` and `cargo test`. Integration tests run in CI using the same scripts (slapd from apt, LLDAP binary).

## 8. Milestones

*Status (2026-10-23): milestones 1–14 are implemented on `feature/ldap-browser`.*

1. **Skeleton**: cargo project, CLI, file logging, terminal setup/teardown with panic hook, empty layout, quit key.
2. **Config & secrets**: structs, defaults, validation, password resolution order, permission warning, example files, unit tests.
3. **LDAP core**: connect (ldap/ldaps, `ca_cert`, insecure), bind with AD error decoding, RootDSE and flavor detection, base read with ranged retrieval, one-level listing (paged when supported). A headless `--check` flag connects, binds, prints the RootDSE summary and exits.
4. **Test servers**: slapd and LLDAP scripts, seed data, first integration tests (connect/bind/TLS cases).
5. **Browse UI**: profile picker, login prompt with retry limit, lazy tree with naming-context roots, child limit and filter, entry pane, value viewer, status bar with TLS badges, help, responsive layout.
6. **Search**: dialog, five search types with per-flavor filters, results pane, abandon, history.
7. **Follow & navigate**: DN detection, follow, back/forward, go-to-DN with path reveal, members/memberOf views including nested membership and the AD primary group.
8. **Polish**: value decoders in the UI, OSC 52 clipboard, operational attribute toggle, icons and colours with ASCII fallback, `NO_COLOR`, error message mapping.
9. **Docs**: README (install, config reference, key bindings, AD-over-LDAPS guidance, `insecure_skip_verify` and secrets permission notes, LLDAP and GC ports).
10. **Entry tools** (5.6.2, 5.6.5): attribute filter in the entry pane; mark and diff two entries.
11. **Recall** (5.6.3, 5.6.4, 5.6.9): persisted search history, atomic `config.json` writer, the Saved tab with `Ctrl-S`, bookmarks with `★` markers.
12. **Results** (5.6.7, 5.6.8, 5.6.1): type-aware sorting, the column picker with re-run on new attributes, the membership tree, then export in LDIF, JSON and CSV for entries, results and trees.
13. **Mouse** (5.6.6): mouse capture with `--no-mouse`, hit-testing from recorded layout, click, double-click, scroll, header sort, right-click menu.
14. **Docs update**: README key table, config reference and the Shift-to-select note for mouse mode.

## 9. Decisions log

| Topic | Decision |
|---|---|
| StartTLS | Not supported |
| Secrets storage | Plaintext `secrets.json`, `0600` warning |
| Missing password | Prompt at connect, kept in memory, max 3 attempts |
| Target directories | AD primary; OpenLDAP and LLDAP supported |
| Platform | Linux only |
| Integration test servers | Native `slapd` and LLDAP processes; no Docker |
| Tree roots | Base DN expanded, plus other naming contexts collapsed; `show_all_naming_contexts` (default `true`) |
| Ad-hoc `--url` | Not included; profiles only |
| Clipboard | OSC 52 |
| Writing `config.json` | Yes, for `search.saved` and `bookmarks` only: re-read, change those arrays, write atomically, preserve key order and permissions. `secrets.json` is never written |
| Search history | `$XDG_STATE_HOME/ldaptui/history.json`, per profile, 50 entries per search type |
| Mouse | On by default, `--no-mouse` / `"mouse": false` to disable; no drag selection |
| Result sorting | Client-side on fetched results; adding a column may re-run the search |
| Export redaction | Secret attributes always written as `<redacted>` |
| Membership tree | Lazy, one base read per expanded node, cycles marked `↻`, depth 10 |

## 10. Directory server compatibility

`flavor: "auto"` detection from the RootDSE:
1. `forestFunctionality` or `isGlobalCatalogReady` present → **AD**.
2. `objectClass` contains `OpenLDAProotDSE` → **OpenLDAP**.
3. `vendorName` contains "LLDAP" → **LLDAP**. *Verified against LLDAP v0.6.3 (`vendorName: LLDAP`). This check runs first, because LLDAP's RootDSE also contains `isGlobalCatalogReady: false`; for AD, `isGlobalCatalogReady` only counts when it is `TRUE`.*
4. Otherwise → **generic**, which uses the OpenLDAP defaults without overlays.

The detected flavor is shown in the status bar. An explicit `flavor` in config always wins.

### Active Directory (primary)
- **User filter**: `(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=*{q}*)(cn=*{q}*)(displayName=*{q}*)(mail=*{q}*)(userPrincipalName=*{q}*)))`
- **Group filter**: `(&(objectClass=group)(|(cn=*{q}*)(sAMAccountName=*{q}*)))`
- **Ranged attribute retrieval**: AD returns large multi-valued attributes in chunks, as `member;range=0-1499`. The client re-requests `member;range=1500-*` and so on until the range ends in `*`, then merges the values. This applies to the entry view and the members view, so group membership is never silently truncated.
- **Primary group**: `memberOf` never includes a user's primary group (usually Domain Users). The memberOf view resolves `primaryGroupID` by combining the domain SID with that RID and finding the group with `(objectSid=<sid>)`. That group is listed with a "(primary)" tag.
- **Nested membership**: `(member:1.2.840.113556.1.4.1941:=<dn>)`, searched from the domain root.
- **Decoders**:
  - `objectGUID` and `objectSid`
  - `tokenGroups`, shown as SIDs resolved to names on demand
  - FILETIME attributes (`pwdLastSet`, `lastLogon`, `lastLogonTimestamp`, `accountExpires`, `badPasswordTime`, `lockoutTime`), with `0` and `0x7FFFFFFFFFFFFFFF` shown as "never"
  - `userAccountControl` and `groupType` flags
  - `whenCreated` and `whenChanged` generalized time
- **Bind** accepts a DN, a UPN or `DOMAIN\user`. Bind error codes are decoded (section 3.3).
- **Global Catalog**: ports 3268 and 3269 work as normal profiles. The README notes that the GC only holds a partial set of attributes.
- **Paging**: AD supports the Simple Paged Results control. Its default `MaxPageSize` is 1000; the default `page_size` of 500 is within it.
- **Referrals**: continuation references to ForestDnsZones, DomainDnsZones and Configuration in subtree searches are shown as referral leaves and are not chased.

### OpenLDAP
- **User filter**: `(&(|(objectClass=inetOrgPerson)(objectClass=posixAccount))(|(uid=*{q}*)(cn=*{q}*)(mail=*{q}*)))`
- **Group filter**: `(&(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))(cn=*{q}*))`
- `memberOf` only exists when the overlay is enabled. When it is absent, the memberOf view uses a reverse search: `(|(member=<dn>)(uniqueMember=<dn>)(memberUid=<uid>))`.
- Nested membership is resolved client-side, with cycle detection and a depth limit of 10.
- Paging is used only if the RootDSE `supportedControl` lists `1.2.840.113556.1.4.319`.

### LLDAP
- Default ports are 3890 (LDAP) and 6360 (LDAPS), which must be set explicitly in config.
- **Layout**: `ou=people` and `ou=groups` under the base DN. Users are keyed on `uid`; groups are `groupOfUniqueNames`/`groupOfNames` with `member`/`uniqueMember`. Users have `memberOf`.
- **User filter**: `(&(objectClass=person)(|(uid=*{q}*)(cn=*{q}*)(mail=*{q}*)))`
- **Group filter**: `(&(objectClass=groupOfUniqueNames)(cn=*{q}*))`
- **Graceful degradation**: LLDAP implements a limited subset of LDAP, so:
  - The paged results control is only sent when `supportedControl` lists it. If the server rejects it anyway, retry once without it, and remember that choice for the session.
  - `["*", "+"]` is requested, and the server ignoring `+` is tolerated.
  - No `objectCategory` or extensible-match filters are used.
  - Groups are not nested, so the memberOf view is direct only and the nested toggle is hidden.
- **Verified against LLDAP v0.6.3** (milestone 4):
  - A one-level search on the root DN returns every user and group flattened, and a base search on the root returns all entries. The client therefore synthesizes the root entry and shows its `ou=people` / `ou=groups` children itself.
  - `memberOf` is returned only when requested by name, so entry reads request `*`, `+` and `memberOf`.
  - Attribute names come back lowercase (`objectclass`, `uniquemember`); all lookups are case-insensitive.
  - Groups list each member in both `member` and `uniqueMember`; the members view deduplicates them.
  - The paged results control works but is not advertised in `supportedControl`, so size-limited unpaged searches are used.
  - Substring filters and `member=<dn>` reverse searches work.

### Testing across flavors
- Unit tests cover filter generation for each flavor, flavor detection from recorded RootDSE fixtures (AD, OpenLDAP, LLDAP), ranged-attribute merging and primary-group SID construction.
- Integration tests run the browse and search suite against the local `slapd` and LLDAP processes. AD is covered by fixtures plus the optional env-driven suite against a real DC.

## 11. Implementation notes (deviations found while building)

- **Tree "load more" row** shows "N shown — Enter to load more" rather than "N of M": counting all children would need a full extra search.
- **OpenLDAP group membership** always combines `memberOf` with a reverse search on `member` / `uniqueMember` / `memberUid`, because the memberOf overlay only covers `groupOfNames`, so posixGroup membership would otherwise be missed.
- **DN comparison** canonicalizes escapes (`\2C` and `\,` are equal), because servers return a different escape form from the one users type.
- **Password attributes** (`userPassword`, `unicodePwd`, …) are masked in the entry table and shown only in the value viewer.
- **History** records the entry on screen before each follow/go-to, so Back returns to an entry reached through the tree.
- **Test servers** run as native processes: `scripts/test-slapd.sh` (needs the `slapd` and `ldap-utils` apt packages) and `scripts/test-lldap.sh` (downloads LLDAP v0.6.3). The devcontainer is not modified; install slapd manually.
- **CI** is not set up yet (no remote repository).
