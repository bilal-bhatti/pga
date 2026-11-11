# pga - PostgreSQL roles, databases and privileges in a terminal UI

A terminal UI for the access-control side of PostgreSQL: roles, memberships,
database, schema and object privileges, default privileges, row-level security
and per-role settings. It shows what a role can reach in a database and why,
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

## Tabs

| Tab | Shows | Actions |
|-----|-------|---------|
| 1 Roles | roles, attributes, memberships; `(n)` is the member count | `n` new, `e` attributes, `p` password, `m` join, `x` leave, `D` drop, `Enter` access |
| 2 Databases | databases, owners, sizes, grants | `g` grant, `x` revoke, `o` owner, `Enter` switch database |
| 3 Schemas | schemas in the current database | `g` grant, `x` revoke, `o` owner, `Enter` objects |
| 4 Objects | tables, views, sequences, functions and their grants | `g` grant, `x` revoke, `o` owner |
| 5 Default privs | `ALTER DEFAULT PRIVILEGES` rules | `g` add rule, `x` revoke |
| 6 RLS | tables with row-level security and their policies | |
| 7 Settings | `ALTER ROLE ... SET` and `ALTER DATABASE ... SET` values | |
| 8 Access | everything one role can reach in the current database, and through which grant | `r` pick role |

Every change opens a confirm dialog with the exact SQL; it runs in one
transaction.

## Keys

| Key | Action |
|-----|--------|
| `1`-`8`, `Tab`, `Shift-Tab` | switch tab |
| `j`/`k`, arrows, `PgUp`/`PgDn`, `^d`/`^u`, `Home`/`End` | move |
| `J`/`K` | scroll the detail pane |
| `/` | filter rows; `Esc` clears |
| `?` | toggle the explain pane |
| `s` | show or hide system roles, schemas and objects |
| `b` | pick a database |
| `^r`, `F5` | reload |
| `q`, `^c` | quit |

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
