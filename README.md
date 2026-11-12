# pga - PostgreSQL roles, databases and privileges in a terminal UI

A terminal UI for the access-control side of PostgreSQL: roles, memberships,
database, schema and object privileges, default privileges, row-level security,
per-role settings and extensions. It shows what a role can reach in a database and why,
and runs grants, revokes and role changes after showing the SQL for
confirmation. Press `?` on any tab for a note on the PostgreSQL concept, its
MySQL analogue, and the catalog query behind the view.

## Install

### Shell installer

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/bilal-bhatti/pga/releases/latest/download/pga-installer.sh | sh
```

Downloads a prebuilt binary from the latest
[GitHub release](https://github.com/bilal-bhatti/pga/releases) into
`~/.cargo/bin`. macOS (Apple Silicon and Intel) and Linux x86_64 are published.

### Homebrew

```sh
brew install bilal-bhatti/taps/pga
```

### From source

```sh
cargo install --git https://github.com/bilal-bhatti/pga
# or, from a checkout: cargo install --path .
```

Requires a Rust toolchain. pga is not on crates.io; that name belongs to
another project.

## Usage

```
pga [options] [conninfo]

  conninfo            "host=... user=... dbname=..." or postgres://user@host:port/db
  -h, --host HOST     server host or socket directory
  -p, --port PORT     server port
  -U, --username USER role to connect as
  -d, --dbname DB     database to start in (default: postgres)
  -W, --password      prompt for a password
  -?, --help          this text
```

Unset options fall back to `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`,
`PGPASSWORD`, `PGSSLMODE` and `~/.pgpass`, as in psql.

## Navigation

pga follows PostgreSQL's layout: the server holds roles and databases, a
database holds schemas, a schema holds objects. `Enter` opens the selected
row, `Esc` goes back, and the line above the tabs shows the path, e.g.
`Databases › lmsdb › app`.

| Place | Reached by | Tabs |
|-------|------------|------|
| Server | start, `r`, `d` | Roles, Databases, Settings |
| Role | `Enter` on a role, a membership, or a role row in Access | Access, Memberships, Settings |
| Database | `Enter` on a database; pga connects to it | Schemas, Objects, Default privs, RLS, Settings, Extensions |
| Schema | `Enter` on a schema | Objects, Default privs, RLS |

| Tab | Shows | Actions |
|-----|-------|---------|
| Roles | roles, attributes, memberships; `(n)` is the member count | `n` new, `e` attributes, `p` password, `m` join, `x` leave, `D` drop |
| Access | everything the role can reach in the connected database, and through which grant | role actions |
| Memberships | the groups the role belongs to and the roles that belong to it, with INHERIT / SET / ADMIN | role actions |
| Databases | databases, owners, sizes, grants | `n` new, `g` grant, `x` revoke, `o` owner |
| Schemas | schemas, owners, grants | `g` grant, `x` revoke, `o` owner |
| Objects | tables, views, sequences, functions and their grants | `g` grant, `x` revoke, `o` owner |
| Default privs | `ALTER DEFAULT PRIVILEGES` rules | `g` add rule, `x` revoke |
| RLS | tables with row-level security and their policies | |
| Settings | `ALTER ROLE ... SET` and `ALTER DATABASE ... SET` values for the place | |
| Extensions | installed and available extensions, their schema, owner and what installing needs | `n` install |

Inside a role, the role actions (`e`, `p`, `m`, `x`, `D`) apply to that role.
Every change opens a confirm dialog with the exact SQL (`j`/`k` scroll a long
one); it runs in one transaction, except `CREATE DATABASE`, which PostgreSQL
does not allow inside a transaction block.

Creating a role or a database continues with an access step: for a new role,
`CONNECT` on databases and group memberships; for a new database, which roles
get `CONNECT` and whether to revoke it from `PUBLIC`. `Esc` skips it; the role
or database already exists.

`D` (drop role) reads what the role still holds in every database and lists it
as `REVOKE` statements to tick, then asks you to type the role name. It runs one
confirm per database, each in its own transaction; the last one, in the
connected database, ends with `DROP ROLE`. Objects, databases or policies the
role owns or is named in are listed instead; change those first.

## Keys

| Key | Action |
|-----|--------|
| `Enter`, `→`, `l` | open the selected row |
| `Esc`, `←`, `h` | back; the first `Esc` clears an active filter |
| `1`-`6`, `Tab`, `Shift-Tab` | switch tab |
| `r`, `d` | jump to Roles or Databases |
| `j`/`k`, arrows, `PgUp`/`PgDn`, `^d`/`^u`, `Home`/`End` | move |
| `J`/`K` | scroll the detail pane |
| `/` | filter rows |
| `?` | toggle the explain pane |
| `s` | show or hide system roles, schemas and objects |
| `b` | connect to another database |
| `c` | copy a connection string (see below) |
| `^r`, `F5` | reload |
| `q`, `^c` | quit |

## Connection strings

`c` picks a login role, a database and, for the connected database, a schema,
then offers the result as a libpq URL or as `keyword=value` conninfo. A schema
sets `search_path` to that schema and `public` through `options`. pga shows the
string and sends it to the clipboard with an OSC 52 escape; terminals without
OSC 52 (e.g. Terminal.app) ignore it, and tmux needs `set-clipboard on`. No
password is included.

## Limitations

- TLS encrypts but does not verify the server certificate, as libpq's
  `sslmode=prefer`/`require`. `verify-ca` and `verify-full` are rejected.
- Per-membership `INHERIT`, `SET` and `ADMIN` options need PostgreSQL 16+.
  Older servers show and grant memberships without them.
- The Linux binary links the system OpenSSL 3 (Ubuntu 22.04+, Debian 12+).

## Development

```sh
cargo test
cargo build
cargo build --release
```

Conventions, verification and the release process: [AGENTS.md](AGENTS.md).
