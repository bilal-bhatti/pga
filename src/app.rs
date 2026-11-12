use std::io::Write;

use anyhow::Result;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Constraint::{self, Fill, Length};
use ratatui::widgets::TableState;

use crate::catalog::{self, Access, Local, Role, Server, Shared, grantees, system_schema};
use crate::conn::{self, Conn};
use crate::wizard::{Action, Ctx, Flow, Next, Outcome, StepKind, Target, Wizard};

/// A list in the left pane. Which ones a place offers is `Level::tabs`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Roles,
    Databases,
    Settings,
    Access,
    Memberships,
    Schemas,
    Objects,
    Defaults,
    Rls,
    Extensions,
}

impl Tab {
    pub fn title(self) -> &'static str {
        match self {
            Tab::Roles => "Roles",
            Tab::Databases => "Databases",
            Tab::Settings => "Settings",
            Tab::Access => "Access",
            Tab::Memberships => "Memberships",
            Tab::Schemas => "Schemas",
            Tab::Objects => "Objects",
            Tab::Defaults => "Default privs",
            Tab::Rls => "RLS",
            Tab::Extensions => "Extensions",
        }
    }
}

#[derive(PartialEq)]
pub enum Level {
    Server,
    Role(u32),
    /// Always the connected database, `App::db`.
    Database(String),
    /// A schema in the connected database.
    Schema(String),
}

impl Level {
    pub fn tabs(&self) -> &'static [Tab] {
        match self {
            Level::Server => &[Tab::Roles, Tab::Databases, Tab::Settings],
            Level::Role(_) => &[Tab::Access, Tab::Memberships, Tab::Settings],
            Level::Database(_) => &[Tab::Schemas, Tab::Objects, Tab::Defaults, Tab::Rls, Tab::Settings, Tab::Extensions],
            Level::Schema(_) => &[Tab::Objects, Tab::Defaults, Tab::Rls],
        }
    }
}

#[derive(Default)]
pub struct View {
    pub table: TableState,
    pub filter: String,
}

/// One entry of the navigation path, with the selection and filter of each of its tabs.
pub struct Place {
    pub level: Level,
    pub tab: usize,
    pub views: Vec<View>,
}

impl Place {
    fn new(level: Level) -> Place {
        let views = level.tabs().iter().map(|_| View::default()).collect();
        Place { level, tab: 0, views }
    }
}

pub enum Mode {
    Normal,
    Filter,
    Wizard(Box<Wizard>),
    /// The action and how far its SQL is scrolled.
    Confirm(Action, u16),
    /// `wide` spans the terminal, for text that must stay on one line (a DSN).
    Message { title: String, text: String, error: bool, wide: bool },
}

pub struct ListRow {
    pub cells: Vec<String>,
    /// Index into the tab's source data; the second part is used by tabs
    /// that list nested items.
    pub id: (usize, usize),
    pub dim: bool,
}

pub struct List {
    pub header: Vec<&'static str>,
    pub widths: Vec<Constraint>,
    pub rows: Vec<ListRow>,
}

pub struct App {
    pub conn: Conn,
    pub server: Server,
    pub db: String,
    /// Navigation path. The first entry is `Level::Server` and is never popped.
    pub path: Vec<Place>,
    pub show_system: bool,
    pub explain: bool,
    pub shared: Shared,
    pub local: Local,
    /// Access of the role at the end of the path, if it ends at a role.
    pub access: Option<Access>,
    pub mode: Mode,
    pub status: Option<(String, bool)>,
    pub detail_scroll: u16,
    pub quit: bool,
}

fn row(cells: Vec<String>, id: (usize, usize), dim: bool) -> ListRow {
    ListRow { cells, id, dim }
}

fn check(b: bool) -> String {
    if b { "✓".into() } else { String::new() }
}

impl App {
    pub fn new(mut conn: Conn) -> Result<App> {
        let db = conn.initial_db();
        let server = catalog::server(conn.client(&db)?)?;
        let mut app = App {
            conn,
            server,
            db,
            path: vec![Place::new(Level::Server)],
            show_system: false,
            explain: false,
            shared: Shared::default(),
            local: Local::default(),
            access: None,
            mode: Mode::Normal,
            status: None,
            detail_scroll: 0,
            quit: false,
        };
        app.load_shared()?;
        app.load_local()?;
        Ok(app)
    }

    pub fn place(&self) -> &Place {
        &self.path[self.path.len() - 1]
    }

    fn place_mut(&mut self) -> &mut Place {
        let i = self.path.len() - 1;
        &mut self.path[i]
    }

    pub fn tab(&self) -> Tab {
        let p = self.place();
        p.level.tabs()[p.tab]
    }

    pub fn view(&self) -> &View {
        let p = self.place();
        &p.views[p.tab]
    }

    pub fn view_mut(&mut self) -> &mut View {
        let p = self.place_mut();
        &mut p.views[p.tab]
    }

    fn scope_role(&self) -> Option<&Role> {
        match self.place().level {
            Level::Role(oid) => self.shared.roles.iter().find(|r| r.oid == oid),
            _ => None,
        }
    }

    fn scope_schema(&self) -> Option<&str> {
        match &self.place().level {
            Level::Schema(s) => Some(s),
            _ => None,
        }
    }

    /// Breadcrumb: the top-level tab, then one name per place below it.
    pub fn crumbs(&self) -> Vec<String> {
        let top = &self.path[0];
        let mut out = vec![top.level.tabs()[top.tab].title().to_string()];
        out.extend(self.path[1..].iter().filter_map(|p| match &p.level {
            Level::Server => None,
            Level::Role(oid) => Some(self.role_name(*oid).to_string()),
            Level::Database(name) | Level::Schema(name) => Some(name.clone()),
        }));
        out
    }

    pub fn keys(&self) -> &'static str {
        match (&self.place().level, self.tab()) {
            (Level::Server, Tab::Roles) => "⏎ open  n new  e attributes  p password  m join role  x leave role  D drop",
            (Level::Server, Tab::Databases) => "⏎ open  n new  g grant  x revoke  o owner",
            (_, Tab::Schemas) => "⏎ open  g grant  x revoke  o owner",
            (_, Tab::Extensions) => "n install",
            (_, Tab::Objects) => "g grant  x revoke  o owner",
            (_, Tab::Defaults) => "g add rule  x revoke",
            (Level::Role(_), Tab::Access) => {
                "⏎ open role  b other database  e attributes  p password  m join role  x leave role  D drop"
            }
            (Level::Role(_), Tab::Memberships) => "⏎ open role  e attributes  p password  m join role  x leave role  D drop",
            (Level::Role(_), _) => "e attributes  p password  m join role  x leave role  D drop",
            _ => "",
        }
    }

    fn load_shared(&mut self) -> Result<()> {
        let c = self.conn.client(&self.db)?;
        self.shared = catalog::load_shared(c, self.server.version_num)?;
        Ok(())
    }

    fn load_local(&mut self) -> Result<()> {
        let c = self.conn.client(&self.db)?;
        self.local = catalog::load_local(c)?;
        Ok(())
    }

    fn load_access(&mut self) -> Result<()> {
        self.access = None;
        let Some(role) = self.scope_role().cloned() else { return Ok(()) };
        let c = self.conn.client(&self.db)?;
        self.access = Some(catalog::load_access(c, self.server.version_num, &role, &self.db)?);
        Ok(())
    }

    fn sync_access(&mut self) {
        if let Err(e) = self.load_access() {
            self.fail("Loading access failed", &e);
        }
    }

    fn reload(&mut self) -> Result<()> {
        self.load_shared()?;
        self.load_local()?;
        self.prune();
        self.load_access()
    }

    /// Cuts the path at the first role or schema that no longer exists, e.g. after DROP ROLE.
    fn prune(&mut self) {
        let gone = self.path.iter().position(|p| match &p.level {
            Level::Role(oid) => !self.shared.roles.iter().any(|r| r.oid == *oid),
            Level::Schema(s) => !self.local.schemas.iter().any(|x| &x.name == s),
            Level::Server | Level::Database(_) => false,
        });
        if let Some(i) = gone {
            self.path.truncate(i);
        }
    }

    /// DropRole flow with the role's dependencies in every database that has some.
    fn drop_role(&mut self, role: Role) -> Option<Flow> {
        let deps = (|| -> Result<Vec<catalog::RoleDep>> {
            let c = self.conn.client(&self.db)?;
            let mut deps = catalog::role_deps(c, role.oid, &self.db, true)?;
            for db in catalog::role_dep_dbs(c, role.oid)? {
                deps.extend(catalog::role_deps(self.conn.client(&db)?, role.oid, &db, false)?);
            }
            Ok(deps)
        })();
        match deps {
            Ok(deps) => Some(Flow::DropRole { role, deps }),
            Err(e) => {
                self.fail(&format!("Reading what depends on {}", role.name), &e);
                None
            }
        }
    }

    fn fail(&mut self, title: &str, e: &anyhow::Error) {
        self.mode = Mode::Message { title: title.into(), text: conn::describe(e), error: true, wide: false };
    }

    fn ctx(&self) -> Ctx<'_> {
        Ctx {
            roles: &self.shared.roles,
            members: &self.shared.members,
            schemas: &self.local.schemas,
            dbs: &self.shared.dbs,
            extensions: &self.local.extensions,
            db: &self.db,
            conn: &self.conn,
            v: self.server.version_num,
            user: &self.server.user,
            keywords: &self.server.keywords,
        }
    }

    pub fn role_name(&self, oid: u32) -> &str {
        self.shared.roles.iter().find(|r| r.oid == oid).map_or("?", |r| r.name.as_str())
    }

    /// Rows of the current tab, narrowed to the current place and filter.
    pub fn list(&self) -> List {
        let sys = self.show_system;
        let schema = self.scope_schema();
        let in_scope = |s: &str| schema.is_none_or(|x| x == s);
        let name = |s: &str, n: &str| if schema.is_some() { n.to_string() } else { format!("{s}.{n}") };
        let (header, widths, mut rows): (Vec<&str>, Vec<Constraint>, Vec<ListRow>) = match self.tab() {
            Tab::Roles => (
                vec!["Role (members)", "Login", "Attributes", "Member of"],
                vec![Fill(3), Length(5), Fill(3), Fill(4)],
                self.shared
                    .roles
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| sys || !r.system())
                    .map(|(i, r)| {
                        let groups: Vec<&str> = self
                            .shared
                            .members
                            .iter()
                            .filter(|m| m.member == r.oid)
                            .map(|m| self.role_name(m.role))
                            .collect();
                        let members = self.shared.members.iter().filter(|m| m.role == r.oid).count();
                        let name = if members > 0 { format!("{} ({members})", r.name) } else { r.name.clone() };
                        row(
                            vec![name, check(r.login), r.attributes().join(", "), groups.join(", ")],
                            (i, 0),
                            r.system(),
                        )
                    })
                    .collect(),
            ),
            Tab::Databases => (
                vec!["", "Database", "Owner", "Size", "Granted to"],
                vec![Length(1), Fill(3), Fill(2), Length(9), Fill(4)],
                self.shared
                    .dbs
                    .iter()
                    .enumerate()
                    .map(|(i, d)| {
                        let here = if d.name == self.db { "●" } else { "" };
                        row(
                            vec![
                                here.into(),
                                d.name.clone(),
                                d.owner.clone(),
                                d.size.clone().unwrap_or_else(|| "-".into()),
                                grantees(&d.grants),
                            ],
                            (i, 0),
                            d.template || !d.allow_conn,
                        )
                    })
                    .collect(),
            ),
            Tab::Settings => {
                let role = self.scope_role().map(|r| r.name.as_str());
                let db = matches!(self.place().level, Level::Database(_)).then_some(self.db.as_str());
                (
                    vec!["Role", "Database", "Setting"],
                    vec![Fill(2), Fill(2), Fill(4)],
                    self.shared
                        .settings
                        .iter()
                        .enumerate()
                        .filter(|(_, s)| role.is_none_or(|r| s.role == r) && db.is_none_or(|d| s.db == d))
                        .map(|(i, s)| {
                            let or = |v: &str, all: &str| if v.is_empty() { all.to_string() } else { v.to_string() };
                            row(vec![or(&s.role, "(all roles)"), or(&s.db, "(all databases)"), s.setting.clone()], (i, 0), false)
                        })
                        .collect(),
                )
            }
            Tab::Memberships => {
                let me = match self.place().level {
                    Level::Role(oid) => oid,
                    _ => 0,
                };
                let ms = &self.shared.members;
                let up = ms.iter().enumerate().filter(|(_, m)| m.member == me).map(|(i, m)| (i, "member of", m.role));
                let down = ms.iter().enumerate().filter(|(_, m)| m.role == me).map(|(i, m)| (i, "has member", m.member));
                (
                    vec!["Relation", "Role", "Inherit", "Set", "Admin", "Granted by"],
                    vec![Length(10), Fill(3), Length(7), Length(5), Length(5), Fill(2)],
                    up.chain(down)
                        .map(|(i, rel, other)| {
                            let m = &ms[i];
                            row(
                                vec![
                                    rel.into(),
                                    self.role_name(other).into(),
                                    check(m.inherit),
                                    check(m.set),
                                    check(m.admin),
                                    m.grantor.clone(),
                                ],
                                (i, 0),
                                !m.inherit,
                            )
                        })
                        .collect(),
                )
            }
            Tab::Schemas => (
                vec!["Schema", "Owner", "Contents", "Granted to"],
                vec![Fill(3), Fill(2), Length(16), Fill(4)],
                self.local
                    .schemas
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| sys || !system_schema(&s.name))
                    .map(|(i, s)| {
                        row(
                            vec![
                                s.name.clone(),
                                s.owner.clone(),
                                format!("{} rel, {} fn", s.relations, s.routines),
                                grantees(&s.grants),
                            ],
                            (i, 0),
                            system_schema(&s.name),
                        )
                    })
                    .collect(),
            ),
            Tab::Objects => (
                vec!["Object", "Kind", "Owner", "RLS", "Granted to"],
                vec![Fill(5), Length(12), Fill(2), Length(6), Fill(3)],
                self.local
                    .objects
                    .iter()
                    .enumerate()
                    .filter(|(_, o)| (sys || !system_schema(&o.schema)) && in_scope(&o.schema))
                    .map(|(i, o)| {
                        let rls = match (o.rls, o.force_rls) {
                            (true, true) => "forced",
                            (true, false) => "on",
                            _ => "",
                        };
                        row(
                            vec![
                                name(&o.schema, &o.name),
                                o.kind.label().into(),
                                o.owner.clone(),
                                rls.into(),
                                grantees(&o.grants),
                            ],
                            (i, 0),
                            system_schema(&o.schema),
                        )
                    })
                    .collect(),
            ),
            Tab::Defaults => (
                vec!["Created by", "In schema", "On", "Grantee", "Privileges"],
                vec![Fill(2), Fill(2), Length(10), Fill(2), Fill(4)],
                self.local
                    .defacls
                    .iter()
                    .enumerate()
                    // Rules without a schema apply in every schema.
                    .filter(|(_, d)| d.schema.as_deref().is_none_or(in_scope))
                    .flat_map(|(i, d)| {
                        d.grants.iter().enumerate().map(move |(j, g)| {
                            row(
                                vec![
                                    d.creator.clone(),
                                    d.schema.clone().unwrap_or_else(|| "(all)".into()),
                                    catalog::defacl_keyword(&d.objtype).into(),
                                    g.grantee.clone(),
                                    g.privs_text(),
                                ],
                                (i, j),
                                false,
                            )
                        })
                    })
                    .collect(),
            ),
            Tab::Rls => (
                vec!["Table", "RLS", "Policies", "Owner"],
                vec![Fill(4), Length(10), Length(8), Fill(2)],
                self.local
                    .rls
                    .iter()
                    .enumerate()
                    .filter(|(_, t)| (sys || !system_schema(&t.schema)) && in_scope(&t.schema))
                    .map(|(i, t)| {
                        let state = match (t.enabled, t.forced) {
                            (true, true) => "forced",
                            (true, false) => "on",
                            _ => "off",
                        };
                        row(
                            vec![name(&t.schema, &t.name), state.into(), t.policies.len().to_string(), t.owner.clone()],
                            (i, 0),
                            !t.enabled,
                        )
                    })
                    .collect(),
            ),
            Tab::Extensions => (
                vec!["Extension", "Version", "Schema", "Owner", "Install needs"],
                vec![Fill(3), Length(16), Fill(2), Fill(2), Length(13)],
                self.local
                    .extensions
                    .iter()
                    .enumerate()
                    .map(|(i, e)| {
                        let version = match (&e.installed, &e.default_version) {
                            (Some(v), Some(d)) if v != d => format!("{v} → {d}"),
                            (Some(v), _) => v.clone(),
                            (None, d) => d.clone().unwrap_or_default(),
                        };
                        row(
                            vec![
                                e.name.clone(),
                                version,
                                e.schema.clone().unwrap_or_default(),
                                e.owner.clone().unwrap_or_default(),
                                e.needs().into(),
                            ],
                            (i, 0),
                            e.installed.is_none(),
                        )
                    })
                    .collect(),
            ),
            Tab::Access => {
                let mut rows = Vec::new();
                if let Some(a) = &self.access {
                    for (i, r) in a.reach.iter().enumerate() {
                        let how = if r.usage { "inherits privileges" } else { "only after SET ROLE" };
                        rows.push(row(vec!["role".into(), r.name.clone(), how.into(), String::new()], (0, i), !r.usage));
                    }
                    for (i, it) in a.items.iter().enumerate() {
                        if !sys && it.schema.as_deref().is_some_and(system_schema) {
                            continue;
                        }
                        let mut privs = it.privs.join(", ");
                        if !it.column_privs.is_empty() {
                            privs = format!("{privs} (cols: {})", it.column_privs.join(", ")).trim_start().to_string();
                        }
                        let dim = (it.privs.is_empty() && it.column_privs.is_empty()) || it.blocked.is_some();
                        let name = match (&it.schema, it.kind.as_str()) {
                            (Some(s), k) if k != "schema" => format!("{s}.{}", it.name),
                            _ => it.name.clone(),
                        };
                        rows.push(row(vec![it.kind.clone(), name, privs, it.via.clone()], (1, i), dim));
                    }
                }
                (vec!["Kind", "Object", "Privileges", "Via"], vec![Length(10), Fill(4), Fill(3), Fill(3)], rows)
            }
        };
        let f = self.view().filter.to_lowercase();
        if !f.is_empty() {
            rows.retain(|r| r.cells.iter().any(|c| c.to_lowercase().contains(&f)));
        }
        List { header, widths, rows }
    }

    pub fn selected(&self) -> Option<(usize, usize)> {
        let i = self.view().table.selected()?;
        self.list().rows.get(i).map(|r| r.id)
    }

    /// The role a role action applies to: the place's role, or the selected row on Roles.
    fn selected_role(&self) -> Option<Role> {
        if let Some(r) = self.scope_role() {
            return Some(r.clone());
        }
        if self.tab() != Tab::Roles {
            return None;
        }
        self.selected().map(|(i, _)| self.shared.roles[i].clone())
    }

    /// Copy-DSN defaults: the role and schema in view, else the connected role and none.
    fn dsn_flow(&self) -> Flow {
        let role = self.selected_role().filter(|r| r.login).map_or_else(|| self.server.user.clone(), |r| r.name);
        let selected = self.selected();
        let schema = match (self.scope_schema(), self.tab(), selected) {
            (Some(s), _, _) => Some(s.to_string()),
            (_, Tab::Schemas, Some((i, _))) => Some(self.local.schemas[i].name.clone()),
            (_, Tab::Objects, Some((i, _))) => Some(self.local.objects[i].schema.clone()),
            (_, Tab::Access, Some((1, j))) => self.access.as_ref().and_then(|a| a.items[j].schema.clone()),
            _ => None,
        };
        Flow::Dsn { role, schema: schema.unwrap_or_default() }
    }

    fn target(&self) -> Option<Target> {
        let (i, _) = self.selected()?;
        let db = Some(self.db.clone());
        match self.tab() {
            Tab::Databases => {
                let d = &self.shared.dbs[i];
                Some(Target {
                    what: "DATABASE",
                    alter: "DATABASE",
                    ident: d.ident.clone(),
                    label: d.name.clone(),
                    db: None,
                    privs: catalog::DATABASE_PRIVS.to_vec(),
                    grants: d.grants.clone(),
                })
            }
            Tab::Schemas => {
                let s = &self.local.schemas[i];
                Some(Target {
                    what: "SCHEMA",
                    alter: "SCHEMA",
                    ident: s.ident.clone(),
                    label: s.name.clone(),
                    db,
                    privs: catalog::SCHEMA_PRIVS.to_vec(),
                    grants: s.grants.clone(),
                })
            }
            Tab::Objects => {
                let o = &self.local.objects[i];
                Some(Target {
                    what: o.kind.grant_keyword(),
                    alter: o.kind.alter_keyword(),
                    ident: o.ident.clone(),
                    label: format!("{}.{}", o.schema, o.name),
                    db,
                    privs: o.kind.privs(self.server.version_num),
                    grants: o.grants.clone(),
                })
            }
            _ => None,
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        match std::mem::replace(&mut self.mode, Mode::Normal) {
            Mode::Normal => {
                self.status = None;
                self.key_normal(key);
            }
            Mode::Filter => self.key_filter(key),
            Mode::Wizard(w) => self.key_wizard(w, key),
            Mode::Confirm(a, scroll) => self.key_confirm(a, scroll, key),
            Mode::Message { .. } => {}
        }
    }

    fn set_tab(&mut self, i: usize) {
        let p = self.place_mut();
        if i < p.views.len() {
            p.tab = i;
            self.detail_scroll = 0;
        }
    }

    /// A place already on the path is returned to, not added again. Going from a role to another role keeps the tab.
    fn push(&mut self, level: Level) {
        if let Some(at) = self.path.iter().position(|p| p.level == level) {
            self.path.truncate(at + 1);
        } else {
            let tab = match (&self.place().level, &level) {
                (Level::Role(_), Level::Role(_)) => self.place().tab,
                _ => 0,
            };
            self.path.push(Place { tab, ..Place::new(level) });
        }
        self.detail_scroll = 0;
        self.sync_access();
    }

    fn pop(&mut self) {
        if self.path.len() > 1 {
            self.path.pop();
            self.detail_scroll = 0;
            self.sync_access();
        }
    }

    /// Back to the server level, on `tab`.
    fn home(&mut self, tab: Tab) {
        self.path.truncate(1);
        self.path[0].tab = Level::Server.tabs().iter().position(|t| *t == tab).unwrap_or(0);
        self.detail_scroll = 0;
        self.access = None;
    }

    fn move_sel(&mut self, delta: isize) {
        let n = self.list().rows.len();
        let t = &mut self.view_mut().table;
        if n == 0 {
            t.select(None);
            return;
        }
        let cur = t.selected().unwrap_or(0) as isize;
        t.select(Some((cur + delta).clamp(0, n as isize - 1) as usize));
        self.detail_scroll = 0;
    }

    fn key_normal(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let (i, n) = (self.place().tab, self.place().views.len());
        match key.code {
            KeyCode::Char('c') if ctrl => self.quit = true,
            KeyCode::Char('r') if ctrl => self.refresh(),
            KeyCode::F(5) => self.refresh(),
            KeyCode::Char('d') if ctrl => self.move_sel(10),
            KeyCode::Char('u') if ctrl => self.move_sel(-10),
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char(c @ '1'..='9') => self.set_tab(c as usize - '1' as usize),
            KeyCode::Tab => self.set_tab((i + 1) % n),
            KeyCode::BackTab => self.set_tab((i + n - 1) % n),
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_sel(-1),
            KeyCode::PageDown => self.move_sel(10),
            KeyCode::PageUp => self.move_sel(-10),
            KeyCode::Home => self.move_sel(isize::MIN / 2),
            KeyCode::End => self.move_sel(isize::MAX / 2),
            KeyCode::Char('J') => self.detail_scroll = self.detail_scroll.saturating_add(3),
            KeyCode::Char('K') => self.detail_scroll = self.detail_scroll.saturating_sub(3),
            KeyCode::Char('/') => self.mode = Mode::Filter,
            KeyCode::Esc if !self.view().filter.is_empty() => self.view_mut().filter.clear(),
            KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') => self.pop(),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => self.enter(),
            KeyCode::Char('r') => self.home(Tab::Roles),
            KeyCode::Char('d') => self.home(Tab::Databases),
            KeyCode::Char('?') => {
                self.explain = !self.explain;
                self.detail_scroll = 0;
            }
            KeyCode::Char('s') => self.show_system = !self.show_system,
            KeyCode::Char('b') => self.drive(Flow::UseDb, Vec::new()),
            KeyCode::Char('c') => self.drive(self.dsn_flow(), Vec::new()),
            KeyCode::Char(c) => self.action(c),
            _ => {}
        }
    }

    fn key_filter(&mut self, key: KeyEvent) {
        let view = self.view_mut();
        let typing = match key.code {
            KeyCode::Esc => {
                view.filter.clear();
                false
            }
            KeyCode::Enter => false,
            KeyCode::Backspace => {
                view.filter.pop();
                true
            }
            KeyCode::Char(c) => {
                view.filter.push(c);
                view.table.select(Some(0));
                true
            }
            _ => true,
        };
        if typing {
            self.mode = Mode::Filter;
        }
    }

    fn key_wizard(&mut self, mut w: Box<Wizard>, key: KeyEvent) {
        self.status = None;
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let step = &mut w.step;
        let last = step.visible().len().saturating_sub(1);
        match (&step.kind, key.code) {
            (_, KeyCode::Esc) => return,
            (_, KeyCode::Char('c')) if ctrl => return,
            (_, KeyCode::Enter) => match step.answer() {
                Some(answer) => {
                    w.answers.push(answer);
                    self.drive(w.flow, w.answers);
                    return;
                }
                None if matches!(step.kind, StepKind::Multi) => {
                    self.status = Some(("nothing ticked: Space ticks the row under ›".into(), true));
                }
                None => {}
            },
            (_, KeyCode::Up) => step.cursor = step.cursor.saturating_sub(1),
            (_, KeyCode::Char('p')) if ctrl => step.cursor = step.cursor.saturating_sub(1),
            (_, KeyCode::Down) => step.cursor = (step.cursor + 1).min(last),
            (_, KeyCode::Char('n')) if ctrl => step.cursor = (step.cursor + 1).min(last),
            (StepKind::Multi, KeyCode::Char('k')) => step.cursor = step.cursor.saturating_sub(1),
            (StepKind::Multi, KeyCode::Char('j')) => step.cursor = (step.cursor + 1).min(last),
            (StepKind::Multi, KeyCode::Char(' ')) => {
                if let Some(c) = step.checked.get_mut(step.cursor) {
                    *c = !*c;
                }
            }
            (StepKind::Multi, KeyCode::Char('a')) => {
                let all = step.checked.iter().all(|c| *c);
                step.checked.iter_mut().for_each(|c| *c = !all);
            }
            (StepKind::Pick | StepKind::Input { .. }, KeyCode::Backspace) => {
                step.text.pop();
                step.cursor = 0;
            }
            (StepKind::Pick | StepKind::Input { .. }, KeyCode::Char(c)) => {
                step.text.push(c);
                step.cursor = 0;
            }
            _ => {}
        }
        self.mode = Mode::Wizard(w);
    }

    fn key_confirm(&mut self, action: Action, scroll: u16, key: KeyEvent) {
        let last = action.display.len() as u16;
        let scroll = match key.code {
            KeyCode::Char('y') => {
                self.execute(action);
                return;
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.status = Some(("cancelled".into(), false));
                return;
            }
            KeyCode::Down | KeyCode::Char('j') => scroll.saturating_add(1).min(last),
            KeyCode::Up | KeyCode::Char('k') => scroll.saturating_sub(1),
            KeyCode::PageDown => scroll.saturating_add(10).min(last),
            KeyCode::PageUp => scroll.saturating_sub(10),
            _ => scroll,
        };
        self.mode = Mode::Confirm(action, scroll);
    }

    /// Advances a flow until it needs input or finishes.
    fn drive(&mut self, flow: Flow, mut answers: Vec<Vec<String>>) {
        loop {
            match flow.next(&answers, &self.ctx()) {
                Next::Ask(step) => {
                    self.mode = Mode::Wizard(Box::new(Wizard { flow, answers, step }));
                    return;
                }
                Next::Skip(a) => answers.push(a),
                Next::Abort(msg) => {
                    self.status = Some((msg, true));
                    return;
                }
                Next::Done(o) => {
                    self.outcome(o);
                    return;
                }
            }
        }
    }

    fn outcome(&mut self, o: Outcome) {
        match o {
            Outcome::Run(a) => self.mode = Mode::Confirm(a, 0),
            Outcome::UseDb(db) => {
                self.use_db(db);
            }
            Outcome::Copy(text) => {
                let how = match osc52(&text) {
                    Ok(()) => "Sent to the clipboard with OSC 52. Terminals without OSC 52 (e.g. Terminal.app) ignore \
                               it; tmux passes it on with set-clipboard on.",
                    Err(_) => "Writing to the terminal failed; copy it from here.",
                };
                let text = format!("{text}\n\n{how} No password is included.");
                self.mode = Mode::Message { title: "DSN".into(), text, error: false, wide: true };
            }
            Outcome::Blocked { title, text } => self.mode = Mode::Message { title, text, error: true, wide: false },
        }
    }

    /// Connects to `db`. Places under the old database are replaced by `db` itself.
    fn use_db(&mut self, db: String) -> bool {
        let prev = std::mem::replace(&mut self.db, db);
        if let Err(e) = self.load_local() {
            self.db = prev;
            let _ = self.load_local();
            self.fail("Switching database failed", &e);
            return false;
        }
        if let Some(i) = self.path.iter().position(|p| matches!(p.level, Level::Database(_))) {
            self.path.truncate(i);
            self.path.push(Place::new(Level::Database(self.db.clone())));
        }
        self.sync_access();
        self.status = Some((format!("using database {}", self.db), false));
        true
    }

    fn refresh(&mut self) {
        match self.reload() {
            Ok(()) => self.status = Some(("reloaded".into(), false)),
            Err(e) => self.fail("Reload failed", &e),
        }
    }

    fn enter(&mut self) {
        let Some((i, j)) = self.selected() else { return };
        match self.tab() {
            Tab::Roles => self.push(Level::Role(self.shared.roles[i].oid)),
            Tab::Databases => {
                let d = &self.shared.dbs[i];
                if !d.allow_conn {
                    self.status = Some((format!("{} does not allow connections", d.name), true));
                    return;
                }
                let name = d.name.clone();
                if name != self.db && !self.use_db(name.clone()) {
                    return;
                }
                self.push(Level::Database(name));
            }
            Tab::Schemas => self.push(Level::Schema(self.local.schemas[i].name.clone())),
            Tab::Memberships => {
                let m = &self.shared.members[i];
                let other = if Some(m.member) == self.scope_role().map(|r| r.oid) { m.role } else { m.member };
                self.push(Level::Role(other));
            }
            Tab::Access if i == 0 => {
                let reach = self.access.as_ref().map(|a| a.reach[j].name.as_str());
                if let Some(oid) = self.shared.roles.iter().find(|r| Some(r.name.as_str()) == reach).map(|r| r.oid) {
                    self.push(Level::Role(oid));
                }
            }
            _ => {}
        }
    }

    fn action(&mut self, c: char) {
        let tab = self.tab();
        let roles = tab == Tab::Roles || matches!(self.place().level, Level::Role(_));
        let flow = match (tab, c) {
            (Tab::Roles, 'n') => Some(Flow::CreateRole),
            (Tab::Databases, 'n') => Some(Flow::CreateDb),
            (Tab::Extensions, 'n') => Some(Flow::CreateExtension { db: self.db.clone() }),
            (_, 'e') if roles => self.selected_role().map(Flow::EditRole),
            (_, 'p') if roles => self.selected_role().map(Flow::Password),
            (_, 'm') if roles => self.selected_role().map(Flow::Join),
            (_, 'x') if roles => self.selected_role().map(Flow::Leave),
            (_, 'D') if roles => self.selected_role().and_then(|r| self.drop_role(r)),
            (Tab::Databases | Tab::Schemas | Tab::Objects, 'g') => self.target().map(Flow::Grant),
            (Tab::Databases | Tab::Schemas | Tab::Objects, 'x') => self.target().map(Flow::Revoke),
            (Tab::Databases | Tab::Schemas | Tab::Objects, 'o') => self.target().map(Flow::Owner),
            (Tab::Defaults, 'g') => Some(Flow::DefGrant { db: self.db.clone() }),
            (Tab::Defaults, 'x') => self.selected().map(|(i, j)| {
                let acl = self.local.defacls[i].clone();
                let grant = acl.grants[j].clone();
                Flow::DefRevoke { db: self.db.clone(), acl, grant }
            }),
            _ => None,
        };
        if let Some(flow) = flow {
            self.drive(flow, Vec::new());
        }
    }

    /// Runs the statements in one transaction unless the action opts out, reloads
    /// everything, then starts the action's follow-up flow.
    fn execute(&mut self, action: Action) {
        let db = action.db.clone().unwrap_or_else(|| self.db.clone());
        let result = (|| -> Result<()> {
            let client = self.conn.client(&db)?;
            if !action.transaction {
                for stmt in &action.exec {
                    client.batch_execute(stmt)?;
                }
                return Ok(());
            }
            let mut tx = client.transaction()?;
            for stmt in &action.exec {
                tx.batch_execute(stmt)?;
            }
            tx.commit()?;
            Ok(())
        })();
        let notices = self.conn.take_notices();
        let reloaded = self.reload();
        let ok = result.is_ok();
        match result {
            Err(e) => {
                let mut text = conn::describe(&e);
                for n in &notices {
                    text.push_str(&format!("\n{n}"));
                }
                self.mode = Mode::Message { title: "Statement failed, nothing changed".into(), text, error: true, wide: false };
            }
            Ok(()) if !notices.is_empty() && action.then.is_none() => {
                self.mode = Mode::Message { title: "Done, with notices".into(), text: notices.join("\n"), error: false, wide: false };
            }
            Ok(()) => {
                let mut msg = format!("done: {}", action.display.join("; "));
                for n in &notices {
                    msg.push_str(&format!("  {n}"));
                }
                self.status = Some((msg, false));
            }
        }
        if let Err(e) = reloaded {
            self.fail("Reload failed", &e);
            return;
        }
        if ok && let Some(flow) = action.then {
            self.drive(*flow, Vec::new());
        }
    }
}

/// Puts `text` on the clipboard through the terminal (OSC 52).
fn osc52(text: &str) -> std::io::Result<()> {
    let mut out = std::io::stdout();
    write!(out, "\x1b]52;c;{}\x07", base64(text.as_bytes()))?;
    out.flush()
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() { ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base64;

    #[test]
    fn base64_pads() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
