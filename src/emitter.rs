// Licensed under Apache-2.0 (Genesis extension to sqlparser-rs)

//! PG-targeted SQL emitter.
//!
//! The upstream sqlparser `Display` impl emits MySQL-flavored SQL.
//! This module provides a `PgEmitter` that writes PostgreSQL-executable SQL:
//! - Backtick identifiers → double-quoted identifiers
//! - `?` placeholders → `$N`
//! - `LIMIT offset, count` → `LIMIT count OFFSET offset`
//! - Strips MySQL-only table options (ENGINE=, CHARSET=, COLLATE=, AUTO_INCREMENT=)

use core::fmt;
use core::ops::ControlFlow;

use crate::ast::{
    ColumnOption, CreateTableOptions, Expr, LimitClause, Offset, OffsetRows, OnInsert, SetExpr,
    SqlOption, Statement, Value, VisitMut, VisitorMut,
};
use crate::tokenizer::Token;

/// Options controlling PG SQL emission.
#[derive(Debug, Clone)]
pub struct EmitOptions {
    /// Starting parameter number (default 1).
    pub first_param_index: u32,
    /// Whether to quote all identifiers.
    pub always_quote_identifiers: bool,
}

impl Default for EmitOptions {
    fn default() -> Self {
        Self {
            first_param_index: 1,
            always_quote_identifiers: false,
        }
    }
}

impl EmitOptions {
    /// Default options for PostgreSQL emission.
    pub fn postgres() -> Self {
        Self::default()
    }
}

/// Trait for SQL emission. Implemented by PgEmitter for PostgreSQL output.
pub trait SqlEmitter {
    /// Error type for emission failures.
    type Error;
    /// Emit a complete SQL statement.
    fn emit_statement<W: fmt::Write>(
        &mut self,
        stmt: &Statement,
        out: &mut W,
    ) -> Result<(), Self::Error>;
    /// Emit an expression fragment.
    fn emit_expr<W: fmt::Write>(&mut self, expr: &Expr, out: &mut W) -> Result<(), Self::Error>;
}

/// Emitted PostgreSQL SQL plus placeholder accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedSql {
    /// PostgreSQL SQL text.
    pub sql: String,
    /// Number of placeholders consumed while emitting.
    pub placeholder_count: u32,
}

/// PostgreSQL SQL emitter.
pub struct PgEmitter {
    /// Emission options.
    pub opts: EmitOptions,
    /// Next $N parameter index.
    pub next_param: u32,
}

impl PgEmitter {
    /// Create a new PG emitter with the given options.
    pub fn new(opts: EmitOptions) -> Self {
        let next_param = opts.first_param_index;
        Self { opts, next_param }
    }

    /// Allocate the next $N parameter placeholder.
    pub fn next_placeholder(&mut self) -> String {
        let n = self.next_param;
        self.next_param += 1;
        format!("${n}")
    }

    /// Reset parameter counter (e.g., between statements).
    pub fn reset_params(&mut self) {
        self.next_param = self.opts.first_param_index;
    }

    /// Emit a statement into a string and return the emitted SQL together
    /// with the number of placeholders consumed.
    pub fn emit_statement_to_string(
        &mut self,
        stmt: &Statement,
    ) -> Result<EmittedSql, EmitError> {
        let start = self.next_param;
        let sql = self.rewrite_statement(stmt)?;
        Ok(EmittedSql {
            sql,
            placeholder_count: self.next_param - start,
        })
    }

    /// Emit an expression into a string and return the emitted SQL together
    /// with the number of placeholders consumed.
    pub fn emit_expr_to_string(&mut self, expr: &Expr) -> Result<EmittedSql, EmitError> {
        let start = self.next_param;
        let sql = self.rewrite_expr(expr)?;
        Ok(EmittedSql {
            sql,
            placeholder_count: self.next_param - start,
        })
    }

    fn rewrite_statement(&mut self, stmt: &Statement) -> Result<String, EmitError> {
        validate_statement(stmt)?;

        let mut stmt = stmt.clone();
        let _ = stmt.visit(&mut PgAstTransform {
            next_param: &mut self.next_param,
        });

        Ok(rewrite_backtick_identifiers(&stmt.to_string()))
    }

    fn rewrite_expr(&mut self, expr: &Expr) -> Result<String, EmitError> {
        let mut expr = expr.clone();
        let _ = expr.visit(&mut PgAstTransform {
            next_param: &mut self.next_param,
        });
        Ok(rewrite_backtick_identifiers(&expr.to_string()))
    }
}

struct PgAstTransform<'a> {
    next_param: &'a mut u32,
}

impl PgAstTransform<'_> {
    fn next_placeholder(&mut self) -> String {
        let n = *self.next_param;
        *self.next_param += 1;
        format!("${n}")
    }
}

impl VisitorMut for PgAstTransform<'_> {
    type Break = ();

    fn post_visit_query(
        &mut self,
        query: &mut crate::ast::Query,
    ) -> ControlFlow<Self::Break> {
        if let Some(LimitClause::OffsetCommaLimit { offset, limit }) = query.limit_clause.take() {
            query.limit_clause = Some(LimitClause::LimitOffset {
                limit: Some(limit),
                offset: Some(Offset {
                    value: offset,
                    rows: OffsetRows::None,
                }),
                limit_by: vec![],
            });
        }
        ControlFlow::Continue(())
    }

    fn post_visit_statement(&mut self, statement: &mut Statement) -> ControlFlow<Self::Break> {
        if let Statement::CreateTable(create_table) = statement {
            create_table.table_options = filter_table_options(&create_table.table_options);
        }
        ControlFlow::Continue(())
    }

    fn post_visit_value(
        &mut self,
        value: &mut crate::ast::ValueWithSpan,
    ) -> ControlFlow<Self::Break> {
        value.value = match &value.value {
            Value::Placeholder(_) => Value::Placeholder(self.next_placeholder()),
            Value::DoubleQuotedString(v) => Value::SingleQuotedString(v.clone()),
            other => other.clone(),
        };
        ControlFlow::Continue(())
    }
}

fn filter_table_options(options: &CreateTableOptions) -> CreateTableOptions {
    fn strip(options: &[SqlOption]) -> Vec<SqlOption> {
        options
            .iter()
            .filter(|option| !is_stripped_table_option(option))
            .cloned()
            .collect()
    }

    fn collapse_plain(options: Vec<SqlOption>, kind: fn(Vec<SqlOption>) -> CreateTableOptions) -> CreateTableOptions {
        if options.is_empty() {
            CreateTableOptions::None
        } else {
            kind(options)
        }
    }

    match options {
        CreateTableOptions::With(options) => collapse_plain(strip(options), CreateTableOptions::With),
        CreateTableOptions::Options(options) => {
            collapse_plain(strip(options), CreateTableOptions::Options)
        }
        CreateTableOptions::Plain(options) => {
            collapse_plain(strip(options), CreateTableOptions::Plain)
        }
        CreateTableOptions::TableProperties(options) => {
            collapse_plain(strip(options), CreateTableOptions::TableProperties)
        }
        CreateTableOptions::None => CreateTableOptions::None,
    }
}

fn is_stripped_table_option(option: &SqlOption) -> bool {
    match option {
        SqlOption::KeyValue { key, .. } => matches!(
            key.value.to_ascii_uppercase().as_str(),
            "ENGINE"
                | "CHARSET"
                | "DEFAULT CHARSET"
                | "CHARACTER SET"
                | "DEFAULT CHARACTER SET"
                | "COLLATE"
                | "DEFAULT COLLATE"
                | "AUTO_INCREMENT"
        ),
        SqlOption::NamedParenthesizedList(named) => {
            named.key.value.eq_ignore_ascii_case("ENGINE")
        }
        _ => false,
    }
}

fn validate_statement(stmt: &Statement) -> Result<(), EmitError> {
    match stmt {
        Statement::Insert(insert) => {
            if insert.replace_into {
                return Err(EmitError::UnsupportedNode(
                    "REPLACE INTO requires a rewrite pass before PG emission".into(),
                ));
            }
            if insert.ignore {
                return Err(EmitError::UnsupportedNode(
                    "INSERT IGNORE requires a rewrite pass before PG emission".into(),
                ));
            }
            if matches!(insert.on, Some(OnInsert::DuplicateKeyUpdate(_))) {
                return Err(EmitError::UnsupportedNode(
                    "ON DUPLICATE KEY UPDATE requires a rewrite pass before PG emission".into(),
                ));
            }
            if !insert.assignments.is_empty() {
                return Err(EmitError::UnsupportedNode(
                    "INSERT ... SET requires a rewrite pass before PG emission".into(),
                ));
            }
        }
        Statement::Query(query) => {
            validate_query(query)?;
        }
        Statement::Update(update) => {
            if !update.order_by.is_empty() || update.limit.is_some() {
                return Err(EmitError::UnsupportedNode(
                    "UPDATE ... ORDER BY/LIMIT requires a rewrite pass before PG emission".into(),
                ));
            }
        }
        Statement::Delete(delete) => {
            if !delete.order_by.is_empty() || delete.limit.is_some() {
                return Err(EmitError::UnsupportedNode(
                    "DELETE ... ORDER BY/LIMIT requires a rewrite pass before PG emission".into(),
                ));
            }
        }
        Statement::CreateTable(create_table) => {
            for column in &create_table.columns {
                for option in &column.options {
                    if matches_auto_increment_column_option(&option.option) {
                        return Err(EmitError::UnsupportedNode(
                            "AUTO_INCREMENT column options require a rewrite pass before PG emission"
                                .into(),
                        ));
                    }
                }
            }
        }
        _ => {}
    }

    // TODO: reject additional MySQL-only nodes here as the rewrite pipeline lands
    // (for example table partition selection, SQL_CALC_FOUND_ROWS lowering, and
    // other MySQL-only DDL/DML modifiers not covered by this foundation pass).
    Ok(())
}

fn validate_query(query: &crate::ast::Query) -> Result<(), EmitError> {
    if let SetExpr::Select(select) = query.body.as_ref() {
        if select
            .select_modifiers
            .as_ref()
            .is_some_and(|mods| mods.is_any_set())
        {
            return Err(EmitError::UnsupportedNode(
                "MySQL SELECT modifiers require a rewrite pass before PG emission".into(),
            ));
        }
    }

    Ok(())
}

fn matches_auto_increment_column_option(option: &ColumnOption) -> bool {
    match option {
        ColumnOption::DialectSpecific(tokens) => tokens.iter().any(|token| match token {
            Token::Word(word) => word.value.eq_ignore_ascii_case("AUTO_INCREMENT"),
            other => other
                .to_string()
                .eq_ignore_ascii_case("AUTO_INCREMENT"),
        }),
        _ => false,
    }
}

fn rewrite_backtick_identifiers(sql: &str) -> String {
    let chars: Vec<char> = sql.chars().collect();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '\'' => {
                out.push('\'');
                i += 1;
                while i < chars.len() {
                    let ch = chars[i];
                    out.push(ch);
                    i += 1;
                    if ch == '\'' {
                        if i < chars.len() && chars[i] == '\'' {
                            out.push('\'');
                            i += 1;
                        } else {
                            break;
                        }
                    }
                }
            }
            '"' => {
                out.push('"');
                i += 1;
                while i < chars.len() {
                    let ch = chars[i];
                    out.push(ch);
                    i += 1;
                    if ch == '"' {
                        if i < chars.len() && chars[i] == '"' {
                            out.push('"');
                            i += 1;
                        } else {
                            break;
                        }
                    }
                }
            }
            '$' => {
                if let Some((tag, next_index)) = parse_dollar_quote_start(&chars, i) {
                    let closing = format!("${tag}$");
                    out.push_str(&closing);
                    i = next_index;
                    while i < chars.len() {
                        if matches_delimiter(&chars, i, &closing) {
                            out.push_str(&closing);
                            i += closing.chars().count();
                            break;
                        }
                        out.push(chars[i]);
                        i += 1;
                    }
                } else {
                    out.push('$');
                    i += 1;
                }
            }
            '`' => {
                out.push('"');
                i += 1;
                while i < chars.len() {
                    match chars[i] {
                        '`' if i + 1 < chars.len() && chars[i + 1] == '`' => {
                            out.push('`');
                            i += 2;
                        }
                        '`' => {
                            out.push('"');
                            i += 1;
                            break;
                        }
                        '"' => {
                            out.push('"');
                            out.push('"');
                            i += 1;
                        }
                        ch => {
                            out.push(ch);
                            i += 1;
                        }
                    }
                }
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }

    out
}

fn parse_dollar_quote_start(chars: &[char], start: usize) -> Option<(String, usize)> {
    let mut i = start + 1;
    while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
        i += 1;
    }
    if i >= chars.len() || chars[i] != '$' {
        return None;
    }

    let tag: String = chars[start + 1..i].iter().collect();
    Some((tag, i + 1))
}

fn matches_delimiter(chars: &[char], start: usize, delimiter: &str) -> bool {
    delimiter
        .chars()
        .enumerate()
        .all(|(offset, ch)| chars.get(start + offset) == Some(&ch))
}

/// Error type for PG emission failures.
#[derive(Debug)]
pub enum EmitError {
    /// AST node that cannot be lowered to PG SQL without a prior rewrite pass.
    UnsupportedNode(String),
    /// fmt::Write error.
    Fmt(fmt::Error),
}

impl fmt::Display for EmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmitError::UnsupportedNode(node) => {
                write!(f, "unsupported MySQL node requires lowering: {node}")
            }
            EmitError::Fmt(e) => write!(f, "format error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EmitError {}

impl From<fmt::Error> for EmitError {
    fn from(e: fmt::Error) -> Self {
        EmitError::Fmt(e)
    }
}

impl SqlEmitter for PgEmitter {
    type Error = EmitError;

    fn emit_statement<W: fmt::Write>(
        &mut self,
        stmt: &Statement,
        out: &mut W,
    ) -> Result<(), EmitError> {
        out.write_str(&self.rewrite_statement(stmt)?)?;
        Ok(())
    }

    fn emit_expr<W: fmt::Write>(&mut self, expr: &Expr, out: &mut W) -> Result<(), EmitError> {
        out.write_str(&self.rewrite_expr(expr)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mysql_mode::{MySqlModeFlags, parse_mysql_sql};

    fn emit_one(sql: &str) -> EmittedSql {
        let statements = parse_mysql_sql(sql, MySqlModeFlags::empty()).unwrap();
        let mut emitter = PgEmitter::new(EmitOptions::postgres());
        emitter.emit_statement_to_string(&statements[0]).unwrap()
    }

    #[test]
    fn emits_backtick_identifiers_as_pg_double_quotes() {
        let emitted = emit_one(r#"SELECT `a"b`, `odd``name` FROM `t``1`"#);
        assert_eq!(emitted.sql, r#"SELECT "a""b", "odd`name" FROM "t`1""#);
    }

    #[test]
    fn emits_numbered_placeholders() {
        let emitted = emit_one("SELECT ? + ? FROM t WHERE id = ?");
        assert_eq!(emitted.sql, "SELECT $1 + $2 FROM t WHERE id = $3");
        assert_eq!(emitted.placeholder_count, 3);
    }

    #[test]
    fn rewrites_mysql_limit_offset_comma_form() {
        let emitted = emit_one("SELECT * FROM t LIMIT 5, 10");
        assert_eq!(emitted.sql, "SELECT * FROM t LIMIT 10 OFFSET 5");
    }

    #[test]
    fn strips_mysql_create_table_options() {
        let emitted = emit_one(
            "CREATE TABLE t (id INT) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin AUTO_INCREMENT=42",
        );
        assert_eq!(emitted.sql, "CREATE TABLE t (id INT)");
    }

    #[test]
    fn emits_double_quoted_mysql_strings_as_single_quoted_pg_strings() {
        let emitted = emit_one(r#"SELECT "abc""#);
        assert_eq!(emitted.sql, "SELECT 'abc'");
    }

    #[test]
    fn rejects_insert_ignore_without_lowering() {
        let statements =
            parse_mysql_sql("INSERT IGNORE INTO t (id) VALUES (?)", MySqlModeFlags::empty())
                .unwrap();
        let mut emitter = PgEmitter::new(EmitOptions::postgres());
        let err = emitter.emit_statement_to_string(&statements[0]).unwrap_err();
        assert!(matches!(err, EmitError::UnsupportedNode(_)));
    }

    #[test]
    fn rejects_create_table_auto_increment_column_without_lowering() {
        let statements =
            parse_mysql_sql("CREATE TABLE t (id INT AUTO_INCREMENT)", MySqlModeFlags::empty())
                .unwrap();
        let mut emitter = PgEmitter::new(EmitOptions::postgres());
        let err = emitter.emit_statement_to_string(&statements[0]).unwrap_err();
        assert!(matches!(err, EmitError::UnsupportedNode(_)));
    }
}
