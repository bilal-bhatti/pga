use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Clear, Paragraph, Row, Table, Tabs, Wrap};

use crate::app::{App, Mode, Tab};
use crate::wizard::{Action, Step, StepKind};
use crate::{detail, explain};

const GLOBAL_KEYS: &str = "1-8/Tab switch  j/k move  J/K scroll detail  / filter  ? explain  s system objects  b database  ^r reload  q quit";

pub fn draw(f: &mut Frame, app: &mut App) {
    let [head, _, tabs, body, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(2),
    ])
    .areas(f.area());

    let mut header = vec![
        Span::styled(" pga ", Style::new().black().on_cyan().bold()),
        Span::raw(format!("  {}@{}", app.server.user, app.conn.endpoint())),
        Span::raw(format!("  PostgreSQL {}", app.server.version)),
        Span::raw("  db: "),
        Span::styled(app.db.clone(), Style::new().cyan().bold()),
    ];
    if app.server.superuser {
        header.push(Span::styled("  superuser", Style::new().red()));
    }
    f.render_widget(Line::from(header), head);

    let titles: Vec<String> = Tab::ALL.iter().enumerate().map(|(i, t)| format!("{} {}", i + 1, t.title())).collect();
    f.render_widget(Tabs::new(titles).select(app.tab as usize).highlight_style(Style::new().black().on_cyan()), tabs);

    let [left, right] = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(body);
    draw_list(f, app, left);

    let (title, lines) = if app.explain {
        (format!(" Explain: {} ", app.tab.title()), explain::lines(app))
    } else {
        (" Details ".to_string(), detail::lines(app))
    };
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(title)).wrap(Wrap { trim: false }).scroll((app.detail_scroll, 0)),
        right,
    );

    let first = match (&app.mode, &app.status) {
        (Mode::Filter, _) => Line::from(vec![
            Span::styled(" / ", Style::new().black().on_yellow()),
            Span::raw(format!(" {}▏  Enter keep  Esc clear", app.views[app.tab as usize].filter)),
        ]),
        (_, Some((msg, true))) => Line::from(Span::styled(format!(" {msg}"), Style::new().red())),
        (_, Some((msg, false))) => Line::from(Span::styled(format!(" {msg}"), Style::new().green())),
        _ => Line::from(Span::styled(format!(" {}", app.tab.keys()), Style::new().cyan())),
    };
    let [l1, l2] = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(foot);
    f.render_widget(first, l1);
    f.render_widget(Line::from(Span::styled(format!(" {GLOBAL_KEYS}"), Style::new().dark_gray())), l2);

    match &app.mode {
        Mode::Wizard(w) => draw_step(f, &w.step),
        Mode::Confirm(a) => draw_confirm(f, a, &app.db),
        Mode::Message { title, text, error } => draw_message(f, title, text, *error),
        _ => {}
    }
}

fn draw_list(f: &mut Frame, app: &mut App, area: Rect) {
    let tab = app.tab;
    let list = app.list(tab);
    let n = list.rows.len();
    let mut title = format!(" {} ({n})", tab.title());
    if tab == Tab::Access {
        match &app.access {
            Some(a) => title = format!(" Access of {} in {} ({n})", a.role.name, a.db),
            None => title = " Access: press r to pick a role".into(),
        }
    } else if tab.local() {
        title.push_str(&format!(" in {}", app.db));
    }
    let filter = &app.views[tab as usize].filter;
    if !filter.is_empty() {
        title.push_str(&format!("  filter: {filter}"));
    }
    if !app.show_system && matches!(tab, Tab::Roles | Tab::Schemas | Tab::Objects | Tab::Rls | Tab::Access) {
        title.push_str("  (system hidden)");
    }
    title.push(' ');

    let state = &mut app.views[tab as usize].table;
    match state.selected() {
        _ if n == 0 => state.select(None),
        None => state.select(Some(0)),
        Some(i) if i >= n => state.select(Some(n - 1)),
        _ => {}
    }

    let header = Row::new(list.header.iter().map(|h| Cell::from(*h))).style(Style::new().yellow().bold());
    let rows = list.rows.into_iter().map(|r| {
        let dim = r.dim;
        let row = Row::new(r.cells);
        if dim { row.style(Style::new().dark_gray()) } else { row }
    });
    let table = Table::new(rows, list.widths)
        .header(header)
        .block(Block::bordered().title(title))
        .row_highlight_style(Style::new().reversed());
    f.render_stateful_widget(table, area, state);
}

fn popup(f: &mut Frame, title: &str, color: Color, w: u16, h: u16) -> Rect {
    let area = f.area().centered(Constraint::Percentage(w), Constraint::Percentage(h));
    f.render_widget(Clear, area);
    let block = Block::bordered().title(format!(" {title} ")).border_style(Style::new().fg(color));
    let inner = block.inner(area);
    f.render_widget(block, area);
    inner
}

fn draw_step(f: &mut Frame, step: &Step) {
    let inner = popup(f, "Step", Color::Cyan, 70, 70);
    let mut lines = vec![Line::from(Span::styled(step.title.clone(), Style::new().bold()))];
    if let Some(h) = &step.hint {
        lines.push(Line::from(Span::styled(h.clone(), Style::new().dark_gray())));
    }
    lines.push(Line::default());
    let help = match step.kind {
        StepKind::Pick => {
            lines.push(Line::from(vec![Span::styled("filter: ", Style::new().dark_gray()), Span::raw(format!("{}▏", step.text))]));
            "type to filter  ↑/↓ move  Enter choose  Esc cancel"
        }
        StepKind::Multi => "j/k move  Space toggle  a all  Enter continue  Esc cancel",
        StepKind::Input { masked } => {
            let shown = if masked { "•".repeat(step.text.chars().count()) } else { step.text.clone() };
            lines.push(Line::from(format!("> {shown}▏")));
            "Enter continue  Esc cancel"
        }
    };
    let visible = step.visible();
    let room = (inner.height as usize).saturating_sub(lines.len() + 2).max(1);
    let offset = step.cursor.saturating_sub(room - 1);
    for (pos, &i) in visible.iter().enumerate().skip(offset).take(room) {
        let mark = match step.kind {
            StepKind::Multi => if step.checked[i] { "[x] " } else { "[ ] " },
            _ => "",
        };
        let text = format!("{mark}{}", step.opts[i].label);
        lines.push(if pos == step.cursor {
            Line::from(Span::styled(format!("› {text}"), Style::new().reversed()))
        } else {
            Line::from(format!("  {text}"))
        });
    }
    if matches!(step.kind, StepKind::Pick) && visible.is_empty() {
        lines.push(Line::from(Span::styled("  no match", Style::new().dark_gray())));
    }
    let [body, foot] = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(inner);
    f.render_widget(Paragraph::new(lines), body);
    f.render_widget(Line::from(Span::styled(help, Style::new().dark_gray())), foot);
}

fn draw_confirm(f: &mut Frame, a: &Action, current: &str) {
    let inner = popup(f, "Confirm", Color::Yellow, 70, 50);
    let db = a.db.as_deref().unwrap_or(current);
    let mut lines = vec![Line::from(format!("Run in database {db}:")), Line::default()];
    for s in &a.display {
        lines.push(Line::from(Span::styled(format!("{s};"), Style::new().cyan().bold())));
    }
    if let Some(n) = &a.note {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(n.clone(), Style::new().yellow())));
    }
    let [body, foot] = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(inner);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), body);
    f.render_widget(Line::from(Span::styled("y run   n/Esc cancel", Style::new().bold())), foot);
}

fn draw_message(f: &mut Frame, title: &str, text: &str, error: bool) {
    let color = if error { Color::Red } else { Color::Yellow };
    let inner = popup(f, title, color, 60, 40);
    let [body, foot] = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(inner);
    f.render_widget(Paragraph::new(text.to_string()).wrap(Wrap { trim: false }), body);
    f.render_widget(Line::from(Span::styled("any key to close", Style::new().dark_gray())), foot);
}
