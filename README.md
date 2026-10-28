# LdapTui

A read-only terminal browser for LDAP and LDAPS directories, built with Rust and
[Ratatui](https://ratatui.rs). Active Directory is the primary target; OpenLDAP and LLDAP are
also supported. Linux only.

- Browse the directory tree (loaded lazily, with paging for large OUs)
- View entries, including decoded AD values (GUIDs, SIDs, timestamps, `userAccountControl`, `groupType`)
- Follow DN-valued attributes (`member`, `memberOf`, `manager`, …) with back/forward history
- Search for users and groups, by DN, by attribute, or with a raw LDAP filter
- Show a group's members, or the groups an entry belongs to (including nested groups and the AD primary group)
- Connect over `ldap://` or `ldaps://`, optionally skipping certificate checks per profile
- Filter an entry's attributes by name, and diff two entries side by side
- Saved searches and bookmarks kept in `config.json`; search history recalled with the arrow keys
- Sortable results with configurable columns (dates and numbers sort by value)
- Membership tree: expand groups level by level, with cycles marked
- Export entries (LDIF, JSON, CSV), result lists and trees (JSON, CSV)
- Mouse: click, double-click, wheel, header sort, right-click menu

LdapTui never sends add, modify, delete or rename operations.

## Build

```sh
cargo build --release
# binary: target/release/ldaptui
```

## Configure

LdapTui reads two JSON files from `~/.config/ldaptui/` (override with `--config` / `--secrets`):

```sh
mkdir -p ~/.config/ldaptui
cp config.example.json ~/.config/ldaptui/config.json
cp secrets.example.json ~/.config/ldaptui/secrets.json
chmod 600 ~/.config/ldaptui/secrets.json
```

### `config.json`: connection profiles (no secrets)

| Field | Default | Meaning |
|---|---|---|
| `host` | required | Hostname. For LDAPS, use the name in the server's certificate (usually the FQDN, not an IP). |
| `scheme` | `"ldaps"` | `"ldap"` or `"ldaps"` |
| `port` | 389 / 636 | LLDAP uses 3890 / 6360; AD Global Catalog uses 3268 / 3269 |
| `flavor` | `"auto"` | `"ad"`, `"openldap"`, `"lldap"` or `"auto"` (detected from the RootDSE) |
| `base_dn` | discovered | Defaults to the server's `defaultNamingContext` |
| `insecure_skip_verify` | `false` | Skip TLS certificate validation (LDAPS only). Shows a red **INSECURE TLS** badge. |
| `ca_cert` | none | PEM file with your CA, added to the system roots. Preferred over `insecure_skip_verify`. Relative paths are resolved from the config file's directory. |
| `credentials` | none | Key into `secrets.json`; omit or `null` for anonymous bind |
| `timeout_secs` | 10 | Connect and per-operation timeout |
| `page_size` | 500 | Paged-results page size (AD's default maximum is 1000) |
| `size_limit` | 5000 | Maximum search results |
| `tree_child_limit` | 1000 | Children loaded per tree node before "load more" |
| `show_all_naming_contexts` | `true` | Also list other naming contexts (AD Configuration, Schema, DNS zones) as tree roots |
| `search.user_filter`, `search.group_filter` | per flavor | Override the user/group search filter; `{q}` is replaced by the escaped search text |
| `search.saved` | `[]` | Saved searches for the profile: `{ "name", "filter", "base"?, "scope"? }`. A top-level `search.saved` applies to every profile. `{q}` in a filter prompts for text when run. Written by the app on `Ctrl-S` |
| `bookmarks` | `[]` | Bookmarks for the profile: `{ "name", "dn" }`. Written by the app on `B` |
| `results.columns` | per flavor | Default result columns after the name: `{ "users": [...], "groups": [...], "other": [...] }`. Attribute names, plus the computed columns `parent`, `members` (count) and `kind`. Defaults for AD: users `sAMAccountName, mail, userAccountControl, lastLogonTimestamp`; groups `description, groupType, members` |
| `export.dir` | home directory | Directory offered in the export dialog (`~` is expanded) |
| `results.sort` | `name` | Default sort column, with an optional `:desc` suffix, e.g. `lastLogonTimestamp:desc`. Dates and numbers sort by value; missing and "never" values go last |

`default_profile` picks the profile pre-selected in the picker. With a single profile, or with
`--profile NAME`, LdapTui connects straight away.

### `secrets.json`: credentials (plaintext, keep it `chmod 600`)

```json
{
  "corp-ad-reader": { "bind_dn": "CN=svc-ldapread,OU=Service Accounts,DC=example,DC=local", "password": "…" },
  "lab-admin":      { "username": "admin@lab.example.local" },
  "lldap-admin":    { "bind_dn": "uid=admin,ou=people,dc=example,dc=local", "password_env": "LLDAP_ADMIN_PASSWORD" }
}
```

- `bind_dn` (alias `username`) may be a DN, an AD UPN (`user@domain`) or `DOMAIN\user`.
- The password comes from `password`, else the environment variable named in `password_env`,
  else you are prompted when connecting. If the credential key or `bind_dn` is missing, you are
  prompted for both.
- After 3 failed logins LdapTui stops retrying so it doesn't lock the account.
- LdapTui warns at startup if the file is readable by other users. Passwords are never logged or written anywhere.

## Run

```sh
ldaptui                      # profile picker
ldaptui -p corp-ad           # connect to a profile directly
ldaptui -p corp-ad --check   # connect, bind, print a RootDSE summary, exit (no TUI)
```

Other options: `--ascii` (no Unicode symbols), `--no-mouse`, `--log-level debug`. `NO_COLOR` is respected.
Logs go to `~/.local/state/ldaptui/ldaptui.log.*` (rotated daily, 7 kept). Search history is kept in
`~/.local/state/ldaptui/history.json` (per profile and search type, 50 entries each; filters only, never results).

Saving a search or a bookmark rewrites `config.json`: the file is re-read first, only the `search.saved` and
`bookmarks` arrays change, key order and permissions are kept, and the write is atomic. `secrets.json` is never written.

### Keys

| Key | Action |
|---|---|
| `↑↓` `j k` `PgUp PgDn` `Home End` | Move |
| `→` `l` `Enter` | Tree: expand · Entry: follow DN / view value |
| `←` `h` | Collapse / go to parent |
| `Tab` | Switch between tree (or results) and entry pane |
| `/` | Search: Users · Groups · DN · Attribute · Raw filter · Saved (`Ctrl-←→` changes type; `↑↓` recalls history, `Ctrl-D` forgets an entry; `Ctrl-S` saves the filter to config.json) |
| `:` | Tree: filter the selected node's children by name prefix · Entry: filter attributes by name (live; `Esc` clears) |
| `g` | Go to a DN |
| `B` / `'` | Bookmark the selected DN (saved to config.json) / open the bookmark list (`Enter` open, `d` delete, `e` rename) |
| `f` | Follow the selected DN value |
| `b` `Backspace` / `F` | History back / forward |
| `m` / `M` | Members of a group / groups of an entry (`n` toggles nested) |
| `t` | In a members or groups list: tree view. `→` expands a group (one request per node), `↻` marks a group already on the path (cycle), depth is limited to 10 |
| `s` / `S` / `c` | Results: cycle the sort column / reverse / choose and order columns (adding an unfetched attribute re-runs the search) |
| `v` | View the full value (hex dump for binary) |
| `d` / `D` | Mark the entry for comparison / diff the marked entry against the current one (`a` all attributes, `i` identity attributes, `o` operational, `:` filter, `Tab` side) |
| `o` | Show/hide operational attributes |
| `y` / `Y` | Copy DN / copy value |
| `e` | Export what is in focus: the entry (LDIF, JSON or CSV), the results or membership tree, or a tree node's loaded children (JSON or CSV). Password attributes are always redacted; `Tab` completes the path |
| `r` | Refresh node or entry |
| `Esc` | Cancel a running search / close results or popup |
| `R` / `P` | Reconnect / switch profile |
| `?` | Help |
| `q` `Ctrl-C` | Quit |

Copying uses the terminal's OSC 52 escape sequence, so it works over SSH and in containers if your
terminal allows it (in tmux: `set -g set-clipboard on`).

### Mouse

The mouse is captured by default: click selects a row and focuses its pane, clicking a tree arrow expands or
collapses without opening the entry, double-click acts like `Enter`, the wheel scrolls the pane under the
pointer, clicking a results header sorts by that column, footer hints are clickable, and right-click opens a
context menu. While capture is on, hold `Shift` to select text in the terminal. Disable it with `--no-mouse`
or `"mouse": false` at the top level of `config.json`.

## Security notes

- **Use LDAPS for Active Directory.** DCs that enforce LDAP signing reject simple binds over plain
  `ldap://` (`strongerAuthRequired`). Even where it works, the password crosses the network
  unencrypted; LdapTui shows a yellow **PLAIN** badge when that happens.
- `insecure_skip_verify` disables protection against impersonation of the server. Prefer
  `ca_cert` pointing at your internal CA.
- A certificate name mismatch (for example, connecting by IP) is reported as such; fix `host`
  rather than disabling verification.
- The Global Catalog (3268/3269) only holds a subset of attributes for objects outside its own
  domain, so entries may look incomplete there.
- Password attributes (`userPassword`, `unicodePwd`, …) are masked in the entry table; `v` shows them.

## Directory-specific behaviour

- **Active Directory**: paged results; large multi-valued attributes such as `member` are fetched
  in full via ranged retrieval; nested membership uses `LDAP_MATCHING_RULE_IN_CHAIN`; the
  primary group (usually Domain Users, absent from `memberOf`) is shown and tagged *primary*.
- **OpenLDAP**: group membership combines `memberOf` (if the overlay is enabled) with a search for
  groups listing the entry in `member`, `uniqueMember` or `memberUid`; nested groups are resolved
  client-side with cycle detection.
- **LLDAP**: LLDAP flattens searches on its root DN, so LdapTui shows the root's `ou=people` and
  `ou=groups` containers itself. Paging is not advertised, so plain size-limited searches are used.
  Groups are not nested.

## Development

```sh
cargo test                                   # unit + UI render tests
cargo clippy --all-targets -- -D warnings
```

Integration tests run against local servers (no Docker):

```sh
sudo apt-get install slapd ldap-utils        # once
scripts/test-slapd.sh start                  # OpenLDAP on localhost:10389 / 10636
scripts/test-lldap.sh start                  # LLDAP v0.6.3 on localhost:13890 / 16360 (downloads a release)
cargo test -- --ignored --test-threads=4
scripts/test-slapd.sh stop; scripts/test-lldap.sh stop
```

Both scripts generate a throwaway CA under `target/test-ldap/certs/` (the server certificate is for
`localhost` only, so connecting by `127.0.0.1` exercises the name-mismatch error).

AD can't run locally. `tests/ad.rs` runs against a real domain controller when
`LDAPTUI_AD_HOST`, `LDAPTUI_AD_BIND_DN` and `LDAPTUI_AD_PASSWORD` are set (see the file header).
