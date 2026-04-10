// Licensed under Apache-2.0 (Genesis extension to sqlparser-rs)

//! PG-targeted SQL emitter.
//!
//! The upstream sqlparser `Display` impl emits MySQL-flavored SQL.
//! This module provides a `PgEmitter` that writes PostgreSQL-executable SQL.
//! The emitter is intentionally conservative: it normalizes the MySQL-specific
//! surfaces that the proxy depends on while preserving the rest of the AST's
//! canonical `Display` formatting.

use crate::{
    ast::{CreateTableOptions, Ident, SqlOption, Statement},
    dialect::MySqlDialect,
    keywords::Keyword,
    tokenizer::{Token, Tokenizer},
};
use core::fmt;

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
        let sql = normalized_statement_sql(stmt);
        let tokens = Tokenizer::new(&MySqlDialect {}, &sql)
            .tokenize()
            .map_err(|err| EmitError::UnsupportedNode(err.to_string()))?;
        let rendered = render_postgres_sql(self, &tokens);
        out.write_str(&rendered)?;
        Ok(())
    }
}

fn normalized_statement_sql(stmt: &Statement) -> String {
    let mut stmt = stmt.clone();
    strip_mysql_create_table_options(&mut stmt);
    stmt.to_string()
}

fn strip_mysql_create_table_options(stmt: &mut Statement) {
    let Statement::CreateTable(create) = stmt else {
        return;
    };

    fn keep_option(option: &SqlOption) -> bool {
        let uppercase = |ident: &Ident| ident.value.to_ascii_uppercase();
        match option {
            SqlOption::Ident(ident) => !is_mysql_table_option_key(&uppercase(ident)),
            SqlOption::KeyValue { key, .. } => !is_mysql_table_option_key(&uppercase(key)),
            SqlOption::NamedParenthesizedList(list) => {
                !is_mysql_table_option_key(&list.key.value.to_ascii_uppercase())
            }
            _ => true,
        }
    }

    create.table_options = match &create.table_options {
        CreateTableOptions::With(options) => rebuild_create_table_options(
            options.iter().filter(|o| keep_option(o)).cloned().collect(),
            CreateTableOptions::With,
        ),
        CreateTableOptions::Options(options) => rebuild_create_table_options(
            options.iter().filter(|o| keep_option(o)).cloned().collect(),
            CreateTableOptions::Options,
        ),
        CreateTableOptions::Plain(options) => rebuild_create_table_options(
            options.iter().filter(|o| keep_option(o)).cloned().collect(),
            CreateTableOptions::Plain,
        ),
        CreateTableOptions::TableProperties(options) => rebuild_create_table_options(
            options.iter().filter(|o| keep_option(o)).cloned().collect(),
            CreateTableOptions::TableProperties,
        ),
        CreateTableOptions::None => CreateTableOptions::None,
    };

    fn rebuild_create_table_options(
        filtered: Vec<SqlOption>,
        builder: fn(Vec<SqlOption>) -> CreateTableOptions,
    ) -> CreateTableOptions {
        if filtered.is_empty() {
            CreateTableOptions::None
        } else {
            builder(filtered)
        }
    }
}

fn is_mysql_table_option_key(key: &str) -> bool {
    matches!(
        key,
        "ENGINE"
            | "CHARSET"
            | "DEFAULT CHARSET"
            | "CHARACTER SET"
            | "DEFAULT CHARACTER SET"
            | "COLLATE"
            | "DEFAULT COLLATE"
    )
}

fn render_postgres_sql(emitter: &mut PgEmitter, tokens: &[Token]) -> String {
    let mut out = String::new();
    let mut index = 0;

    while index < tokens.len() {
        if let Some((rendered_limit, consumed)) =
            try_render_limit_offset_clause(emitter, tokens, index)
        {
            while out.ends_with(char::is_whitespace) {
                out.pop();
            }
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&rendered_limit);
            index += consumed;
            continue;
        }

        render_token(emitter, &tokens[index], &mut out);
        index += 1;
    }

    out
}

fn render_token(emitter: &mut PgEmitter, token: &Token, out: &mut String) {
    match token {
        Token::Word(word) if word.quote_style == Some('`') => {
            out.push('"');
            out.push_str(&word.value.replace('"', "\"\""));
            out.push('"');
        }
        Token::Placeholder(value) if value == "?" => out.push_str(&emitter.next_placeholder()),
        _ => out.push_str(&token.to_string()),
    }
}

fn try_render_limit_offset_clause(
    emitter: &mut PgEmitter,
    tokens: &[Token],
    start: usize,
) -> Option<(String, usize)> {
    let Token::Word(word) = &tokens[start] else {
        return None;
    };
    if word.keyword != Keyword::LIMIT {
        return None;
    }

    let first_expr_start = skip_trivia(tokens, start + 1);
    let (first_expr_end, comma_index) = scan_limit_expr_until_comma(tokens, first_expr_start)?;
    let second_expr_start = skip_trivia(tokens, comma_index + 1);
    let second_expr_end = scan_limit_expr_end(tokens, second_expr_start);

    let first = render_token_range(emitter, tokens, first_expr_start, first_expr_end)
        .trim()
        .to_string();
    let second = render_token_range(emitter, tokens, second_expr_start, second_expr_end)
        .trim()
        .to_string();
    if first.is_empty() || second.is_empty() {
        return None;
    }

    Some((format!("LIMIT {second} OFFSET {first}"), second_expr_end - start))
}

fn skip_trivia(tokens: &[Token], mut index: usize) -> usize {
    while index < tokens.len() && matches!(tokens[index], Token::Whitespace(_)) {
        index += 1;
    }
    index
}

fn scan_limit_expr_until_comma(tokens: &[Token], start: usize) -> Option<(usize, usize)> {
    let mut depth = 0usize;
    let mut index = start;

    while index < tokens.len() {
        match &tokens[index] {
            Token::LParen | Token::LBracket | Token::LBrace => depth += 1,
            Token::RParen | Token::RBracket | Token::RBrace => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
            }
            Token::Comma if depth == 0 => return Some((index, index)),
            Token::EOF | Token::SemiColon if depth == 0 => return None,
            _ => {}
        }
        index += 1;
    }

    None
}

fn scan_limit_expr_end(tokens: &[Token], start: usize) -> usize {
    let mut depth = 0usize;
    let mut index = start;

    while index < tokens.len() {
        match &tokens[index] {
            Token::LParen | Token::LBracket | Token::LBrace => depth += 1,
            Token::RParen | Token::RBracket | Token::RBrace => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            Token::SemiColon | Token::EOF if depth == 0 => break,
            Token::Word(word)
                if depth == 0
                    && matches!(
                        word.keyword,
                        Keyword::LIMIT
                            | Keyword::OFFSET
                            | Keyword::FETCH
                            | Keyword::FOR
                            | Keyword::UNION
                            | Keyword::EXCEPT
                            | Keyword::INTERSECT
                            | Keyword::ORDER
                    ) =>
            {
                break;
            }
            _ => {}
        }
        index += 1;
    }

    trim_trailing_trivia(tokens, start, index)
}

fn trim_trailing_trivia(tokens: &[Token], start: usize, mut end: usize) -> usize {
    while end > start && matches!(tokens[end - 1], Token::Whitespace(_)) {
        end -= 1;
    }
    end
}

fn render_token_range(emitter: &mut PgEmitter, tokens: &[Token], start: usize, end: usize) -> String {
    let mut rendered = String::new();
    for token in &tokens[start..end] {
        render_token(emitter, token, &mut rendered);
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dialect::MySqlDialect, parser::Parser};

    fn emit_sql(sql: &str) -> String {
        let stmt = Parser::parse_sql(&MySqlDialect {}, sql).unwrap().remove(0);
        let mut emitter = PgEmitter::new(EmitOptions::postgres());
        let mut out = String::new();
        emitter.emit_statement(&stmt, &mut out).unwrap();
        out
    }

    #[test]
    fn rewrites_placeholders_and_backtick_identifiers() {
        let emitted = emit_sql(r#"SELECT "value", `user`.`name`, ?, ? FROM `accounts`"#);
        assert_eq!(
            emitted,
            r#"SELECT "value", "user"."name", $1, $2 FROM "accounts""#
        );
    }

    #[test]
    fn rewrites_mysql_limit_offset_syntax() {
        let emitted = emit_sql("SELECT * FROM `events` LIMIT 5, 10");
        assert_eq!(emitted, r#"SELECT * FROM "events" LIMIT 10 OFFSET 5"#);
    }

    #[test]
    fn rewrites_nested_mysql_limit_offset_syntax() {
        let emitted = emit_sql(
            "SELECT * FROM (SELECT * FROM `events` LIMIT 1, 2) AS `e` LIMIT (3 + 4), 5",
        );
        assert_eq!(
            emitted,
            r#"SELECT * FROM (SELECT * FROM "events" LIMIT 2 OFFSET 1) AS "e" LIMIT 5 OFFSET (3 + 4)"#
        );
    }

    #[test]
    fn strips_mysql_create_table_options() {
        let emitted = emit_sql(
            "CREATE TABLE `users` (`id` INT) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin",
        );
        assert_eq!(emitted, r#"CREATE TABLE "users" ("id" INT)"#);
    }
}
