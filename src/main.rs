mod app;
mod catalog;
mod conn;
mod detail;
mod explain;
mod ui;
mod wizard;

use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::crossterm::terminal;

use crate::app::App;
use crate::conn::{Conn, Opts};

const USAGE: &str = "\
pga: browse and manage PostgreSQL roles, databases and privileges

usage: pga [options] [conninfo]

  conninfo            \"host=... user=... dbname=...\" or postgres://user@host:port/db
  -h, --host HOST     server host or socket directory
  -p, --port PORT     server port
  -U, --username USER role to connect as
  -d, --dbname DB     database to start in (default: postgres)
  -W, --password      prompt for a password
  -?, --help          this text

Unset options fall back to PGHOST, PGPORT, PGUSER, PGDATABASE, PGPASSWORD,
PGSSLMODE and ~/.pgpass, as in psql.";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pga: {}", conn::describe(&e));
            ExitCode::FAILURE
        }
    }
}

fn parse_args() -> Result<Option<(Opts, bool)>> {
    let mut opts = Opts::default();
    let mut prompt = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().with_context(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "-?" | "--help" => return Ok(None),
            "-h" | "--host" => opts.host = Some(value()?),
            "-p" | "--port" => opts.port = Some(value()?.parse().context("invalid port")?),
            "-U" | "--username" => opts.user = Some(value()?),
            "-d" | "--dbname" => opts.dbname = Some(value()?),
            "-W" | "--password" => prompt = true,
            s if s.starts_with('-') => bail!("unknown option {s} (see --help)"),
            s => opts.conninfo = Some(s.to_string()),
        }
    }
    Ok(Some((opts, prompt)))
}

fn prompt_password(user: &str) -> Result<String> {
    eprint!("Password for {user}: ");
    terminal::enable_raw_mode()?;
    let mut pw = String::new();
    let result = loop {
        match event::read() {
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => match k.code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Esc => break Err(anyhow::anyhow!("cancelled")),
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    break Err(anyhow::anyhow!("cancelled"));
                }
                KeyCode::Backspace => {
                    pw.pop();
                }
                KeyCode::Char(c) => pw.push(c),
                _ => {}
            },
            Ok(_) => {}
            Err(e) => break Err(e.into()),
        }
    };
    terminal::disable_raw_mode()?;
    eprintln!();
    result.map(|()| pw)
}

fn run() -> Result<()> {
    let Some((opts, prompt)) = parse_args()? else {
        println!("{USAGE}");
        return Ok(());
    };
    let mut conn = Conn::new(conn::build_config(&opts)?);
    let db = conn.initial_db();
    if prompt {
        let pw = prompt_password(conn.user())?;
        conn.set_password(&pw);
    }
    let first = conn.client(&db).map(|_| ());
    if let Err(e) = first {
        if !conn::needs_password(&e) {
            return Err(e);
        }
        let pw = prompt_password(conn.user())?;
        conn.set_password(&pw);
        conn.client(&db)?;
    }

    let mut app = App::new(conn)?;
    let mut terminal = ratatui::init();
    let result = (|| -> Result<()> {
        while !app.quit {
            terminal.draw(|f| ui::draw(f, &mut app))?;
            if let Event::Key(k) = event::read()?
                && k.kind == KeyEventKind::Press
            {
                app.on_key(k);
            }
        }
        Ok(())
    })();
    ratatui::restore();
    result
}
