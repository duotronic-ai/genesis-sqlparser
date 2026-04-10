// Licensed under Apache-2.0 (Genesis extension to sqlparser-rs)

//! PG-targeted SQL emitter.
//!
//! The upstream sqlparser `Display` impl emits MySQL-flavored SQL.
//! This module provides a `PgEmitter` that writes PostgreSQL-executable SQL:
//! - Backtick identifiers → double-quoted
//! - `?` placeholders → `$N`
//! - `LIMIT offset, count` → `LIMIT count OFFSET offset`
//! - Strips MySQL-only table options (ENGINE=, CHARSET=, COLLATE=)

use core::fmt;
use crate::ast::Statement;

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
        _stmt: &Statement,
        _out: &mut W,
    ) -> Result<(), EmitError> {
        // Foundation stub — PR7 implements the full PG emitter.
        // Contract: the emitter walks the AST and writes PG-executable SQL.
        // Unsupported nodes that weren't lowered by a rewrite pass produce
        // EmitError::UnsupportedNode.
        todo!("PgEmitter::emit_statement not yet implemented")
    }
}
