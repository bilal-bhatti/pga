use anyhow::Result;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Constraint::{self, Fill, Length};
use ratatui::widgets::TableState;

use crate::catalog::{self, Access, Local, Role, Server, Shared, grantees, system_schema};
use crate::conn::{self, Conn};
use crate::wizard::{Action, Ctx, Flow, Next, Outcome, StepKind, Target, Wizard};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Roles,
    Databases,
    Schemas,
    Objects,
    Defaults,
    Rls,
    Settings,
    Access,
}

impl Tab {
    pub const ALL: [Tab; 8] =
        [Tab::Roles, Tab::Databases, Tab::Schemas, Tab::Objects, Tab::Defaults, Tab::Rls, Tab::Settings, Tab::Access];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Roles => "Roles",
            Tab::Databases => "Databases",
            Tab::Schemas => "Schemas",
            Tab::Objects => "Objects",
            Tab::Defaults => "Default privs",
            Tab::Rls => "RLS",
            Tab::Settings => "Settings",
            Tab::Access => "Access",
        }
    }

    /// Tabs whose data comes from the current database's catalog.
    pub fn local(self) -> bool {
        matches!(self, Tab::Schemas | Tab::Objects | Tab::Defaults | Tab::Rls | Tab::Access)
    }

    pub fn keys(self) -> &'static str {
        match self {
            Tab::Roles => "⏎ access  n new  e attributes  p password  m join role  x leave role  D drop",
            Tab::Databases => "⏎ use database  g grant  x revoke  o owner",
            Tab::Schemas => "⏎ objects  g grant  x revoke  o owner",
            Tab::Objects => "g grant  x revoke  o owner",
            Tab::Defaults => "g add rule  x revoke",
            Tab::Rls | Tab::Settings => "",
            Tab::Access => "r pick role",
        }
    }
}

#[derive(Default)]
pub struct View {
    pub table: TableState,
    pub filter: String,
}

pub enum Mode {
    Normal,
    Filter,
    Wizard(Box<Wizard>),
    Confirm(Action),
    Message { title: String, text: String, error: bool },
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
    pub tab: Tab,
    pub views: [View; 8],
    pub show_system: bool,
    pub explain: bool,
    pub shared: Shared,
    pub local: Local,
    pub access: Option<Access>,
    pub access_role: Option<u32>,
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
            tab: Tab::Roles,
            views: Default::default(),
            show_system: false,
            explain: false,
            shared: Shared::default(),
            local: Local::default(),
            access: None,
            access_role: None,
            mode: Mode::Normal,
            status: None,
            detail_scroll: 0,
            quit: false,
        };
        app.load_shared()?;
        app.load_local()?;
        Ok(app)
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
        let Some(role) = self.access_role.and_then(|oid| self.shared.roles.iter().find(|r| r.oid == oid)).cloned()
        else {
            self.access_role = None;
            return Ok(());
        };
        let c = self.conn.client(&self.db)?;
        self.access = Some(catalog::load_access(c, self.server.version_num, &role, &self.db)?);
        Ok(())
    }

    fn reload(&mut self) -> Result<()> {
        self.load_shared()?;
        self.load_local()?;
        self.load_access()
    }

    fn fail(&mut self, title: &str, e: &anyhow::Error) {
        self.mode = Mode::Message { title: title.into(), text: conn::describe(e), error: true };
    }

    fn ctx(&self) -> Ctx<'_> {
        Ctx {
            roles: &self.shared.roles,
            members: &self.shared.members,
            schemas: &self.local.schemas,
            dbs: &self.shared.dbs,
            v: self.server.version_num,
            user: &self.server.user,
            keywords: &self.server.keywords,
        }
    }

    pub fn role_name(&self, oid: u32) -> &str {
        self.shared.roles.iter().find(|r| r.oid == oid).map_or("?", |r| r.name.as_str())
    }

    pub fn list(&self, tab: Tab) -> List {
        let sys = self.show_system;
        let (header, widths, mut rows): (Vec<&str>, Vec<Constraint>, Vec<ListRow>) = match tab {
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
                    .filter(|(_, o)| sys || !system_schema(&o.schema))
                    .map(|(i, o)| {
                        let rls = match (o.rls, o.force_rls) {
                            (true, true) => "forced",
                            (true, false) => "on",
                            _ => "",
                        };
                        row(
                            vec![
                                format!("{}.{}", o.schema, o.name),
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
                    .filter(|(_, t)| sys || !system_schema(&t.schema))
                    .map(|(i, t)| {
                        let state = match (t.enabled, t.forced) {
                            (true, true) => "forced",
                            (true, false) => "on",
                            _ => "off",
                        };
                        row(
                            vec![format!("{}.{}", t.schema, t.name), state.into(), t.policies.len().to_string(), t.owner.clone()],
                            (i, 0),
                            !t.enabled,
                        )
                    })
                    .collect(),
            ),
            Tab::Settings => (
                vec!["Role", "Database", "Setting"],
                vec![Fill(2), Fill(2), Fill(4)],
                self.shared
                    .settings
                    .iter()
                    .enumerate()
                    .map(|(i, s)| {
                        let or = |v: &str, all: &str| if v.is_empty() { all.to_string() } else { v.to_string() };
                        row(vec![or(&s.role, "(all roles)"), or(&s.db, "(all databases)"), s.setting.clone()], (i, 0), false)
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
        let f = self.views[tab as usize].filter.to_lowercase();
        if !f.is_empty() {
            rows.retain(|r| r.cells.iter().any(|c| c.to_lowercase().contains(&f)));
        }
        List { header, widths, rows }
    }

    pub fn selected(&self) -> Option<(usize, usize)> {
        let i = self.views[self.tab as usize].table.selected()?;
        self.list(self.tab).rows.get(i).map(|r| r.id)
    }

    fn selected_role(&self) -> Option<Role> {
        if self.tab != Tab::Roles {
            return None;
        }
        self.selected().map(|(i, _)| self.shared.roles[i].clone())
    }

    fn target(&self) -> Option<Target> {
        let (i, _) = self.selected()?;
        let db = Some(self.db.clone());
        match self.tab {
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
            Mode::Confirm(a) => self.key_confirm(a, key),
            Mode::Message { .. } => {}
        }
    }

    fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.detail_scroll = 0;
    }

    fn move_sel(&mut self, delta: isize) {
        let n = self.list(self.tab).rows.len();
        let t = &mut self.views[self.tab as usize].table;
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
        let i = self.tab as usize;
        match key.code {
            KeyCode::Char('c') if ctrl => self.quit = true,
            KeyCode::Char('r') if ctrl => self.refresh(),
            KeyCode::F(5) => self.refresh(),
            KeyCode::Char('d') if ctrl => self.move_sel(10),
            KeyCode::Char('u') if ctrl => self.move_sel(-10),
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char(c @ '1'..='8') => self.set_tab(Tab::ALL[c as usize - '1' as usize]),
            KeyCode::Tab => self.set_tab(Tab::ALL[(i + 1) % 8]),
            KeyCode::BackTab => self.set_tab(Tab::ALL[(i + 7) % 8]),
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_sel(-1),
            KeyCode::PageDown => self.move_sel(10),
            KeyCode::PageUp => self.move_sel(-10),
            KeyCode::Home => self.move_sel(isize::MIN / 2),
            KeyCode::End => self.move_sel(isize::MAX / 2),
            KeyCode::Char('J') => self.detail_scroll = self.detail_scroll.saturating_add(3),
            KeyCode::Char('K') => self.detail_scroll = self.detail_scroll.saturating_sub(3),
            KeyCode::Char('/') => self.mode = Mode::Filter,
            KeyCode::Esc => self.views[i].filter.clear(),
            KeyCode::Char('?') => {
                self.explain = !self.explain;
                self.detail_scroll = 0;
            }
            KeyCode::Char('s') => self.show_system = !self.show_system,
            KeyCode::Char('b') => self.drive(Flow::UseDb, Vec::new()),
            KeyCode::Enter => self.enter(),
            KeyCode::Char(c) => self.action(c),
            _ => {}
        }
    }

    fn key_filter(&mut self, key: KeyEvent) {
        let view = &mut self.views[self.tab as usize];
        match key.code {
            KeyCode::Esc => view.filter.clear(),
            KeyCode::Enter => {}
            KeyCode::Backspace => {
                view.filter.pop();
                self.mode = Mode::Filter;
            }
            KeyCode::Char(c) => {
                view.filter.push(c);
                view.table.select(Some(0));
                self.mode = Mode::Filter;
            }
            _ => self.mode = Mode::Filter,
        }
    }

    fn key_wizard(&mut self, mut w: Box<Wizard>, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let step = &mut w.step;
        let last = step.visible().len().saturating_sub(1);
        match (&step.kind, key.code) {
            (_, KeyCode::Esc) => return,
            (_, KeyCode::Char('c')) if ctrl => return,
            (_, KeyCode::Enter) => {
                if let Some(answer) = step.answer() {
                    w.answers.push(answer);
                    self.drive(w.flow, w.answers);
                    return;
                }
            }
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

    fn key_confirm(&mut self, action: Action, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') => self.execute(action),
            KeyCode::Char('n') | KeyCode::Esc => self.status = Some(("cancelled".into(), false)),
            _ => self.mode = Mode::Confirm(action),
        }
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
            Outcome::Run(a) => self.mode = Mode::Confirm(a),
            Outcome::UseDb(db) => self.use_db(db),
            Outcome::Inspect(oid) => {
                self.access_role = Some(oid);
                self.set_tab(Tab::Access);
                self.views[Tab::Access as usize].table.select(Some(0));
                if let Err(e) = self.load_access() {
                    self.fail("Loading access failed", &e);
                }
            }
        }
    }

    fn use_db(&mut self, db: String) {
        let prev = std::mem::replace(&mut self.db, db);
        if let Err(e) = self.load_local().and_then(|_| self.load_access()) {
            self.db = prev;
            let _ = self.load_local().and_then(|_| self.load_access());
            self.fail("Switching database failed", &e);
            return;
        }
        for t in Tab::ALL.into_iter().filter(|t| t.local()) {
            self.views[t as usize] = View::default();
        }
        self.status = Some((format!("using database {}", self.db), false));
    }

    fn refresh(&mut self) {
        match self.reload() {
            Ok(()) => self.status = Some(("reloaded".into(), false)),
            Err(e) => self.fail("Reload failed", &e),
        }
    }

    fn enter(&mut self) {
        let Some((i, _)) = self.selected() else { return };
        match self.tab {
            Tab::Roles => self.outcome(Outcome::Inspect(self.shared.roles[i].oid)),
            Tab::Databases => {
                let d = &self.shared.dbs[i];
                if !d.allow_conn {
                    self.status = Some((format!("{} does not allow connections", d.name), true));
                    return;
                }
                self.use_db(d.name.clone());
                if matches!(self.mode, Mode::Normal) {
                    self.set_tab(Tab::Schemas);
                }
            }
            Tab::Schemas => {
                let filter = format!("{}.", self.local.schemas[i].name);
                let v = &mut self.views[Tab::Objects as usize];
                v.filter = filter;
                v.table.select(Some(0));
                self.set_tab(Tab::Objects);
            }
            _ => {}
        }
    }

    fn action(&mut self, c: char) {
        let flow = match (self.tab, c) {
            (Tab::Roles, 'n') => Some(Flow::CreateRole),
            (Tab::Roles, 'e') => self.selected_role().map(Flow::EditRole),
            (Tab::Roles, 'p') => self.selected_role().map(Flow::Password),
            (Tab::Roles, 'm') => self.selected_role().map(Flow::Join),
            (Tab::Roles, 'x') => self.selected_role().map(Flow::Leave),
            (Tab::Roles, 'D') => self.selected_role().map(Flow::DropRole),
            (Tab::Databases | Tab::Schemas | Tab::Objects, 'g') => self.target().map(Flow::Grant),
            (Tab::Databases | Tab::Schemas | Tab::Objects, 'x') => self.target().map(Flow::Revoke),
            (Tab::Databases | Tab::Schemas | Tab::Objects, 'o') => self.target().map(Flow::Owner),
            (Tab::Defaults, 'g') => Some(Flow::DefGrant { db: self.db.clone() }),
            (Tab::Defaults, 'x') => self.selected().map(|(i, j)| {
                let acl = self.local.defacls[i].clone();
                let grant = acl.grants[j].clone();
                Flow::DefRevoke { db: self.db.clone(), acl, grant }
            }),
            (Tab::Access, 'r') => Some(Flow::Inspect),
            _ => None,
        };
        if let Some(flow) = flow {
            self.drive(flow, Vec::new());
        }
    }

    /// Runs the statements in one transaction, then reloads everything.
    fn execute(&mut self, action: Action) {
        let db = action.db.clone().unwrap_or_else(|| self.db.clone());
        let result = (|| -> Result<()> {
            let mut tx = self.conn.client(&db)?.transaction()?;
            for stmt in &action.exec {
                tx.batch_execute(stmt)?;
            }
            tx.commit()?;
            Ok(())
        })();
        let notices = self.conn.take_notices();
        let reloaded = self.reload();
        match result {
            Err(e) => {
                let mut text = conn::describe(&e);
                for n in &notices {
                    text.push_str(&format!("\n{n}"));
                }
                self.mode = Mode::Message { title: "Statement failed, nothing changed".into(), text, error: true };
            }
            Ok(()) if !notices.is_empty() => {
                self.mode = Mode::Message { title: "Done, with notices".into(), text: notices.join("\n"), error: false };
            }
            Ok(()) => self.status = Some((format!("done: {}", action.display.join("; ")), false)),
        }
        if let Err(e) = reloaded {
            self.fail("Reload failed", &e);
        }
    }
}
