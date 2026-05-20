//! Free-form invariant expression engine.
//!
//! Sprint 3 deliverable: parses strings like
//! `"spend_total <= max_budget_usd"`, `"payment_currency in ('EUR', 'USD')"`,
//! or `"no_external_call_to(domain: 'competitor.com')"` from a [`Policy`]'s
//! `invariants:` list into a small, validated AST that the evaluator can
//! walk against an [`EvaluationContext`] + [`Action`] + [`Binding`].
//!
//! ## Layout
//! - [`lexer`]  — hand-rolled tokenizer with position tracking.
//! - [`parser`] — recursive-descent Pratt parser producing [`Expr`] nodes.
//! - [`eval`]   — tree-walking evaluator over [`Value`]s.
//!
//! ## Grammar (intentionally small)
//!
//! ```text
//! expr      := or_expr
//! or_expr   := and_expr (("||" | "or") and_expr)*
//! and_expr  := not_expr (("&&" | "and") not_expr)*
//! not_expr  := ("!" | "not") not_expr | cmp_expr
//! cmp_expr  := add_expr ((COMP_OP | "in") add_expr)?
//! add_expr  := mul_expr (("+" | "-") mul_expr)*
//! mul_expr  := unary
//! unary     := "-" unary | primary
//! primary   := NUM | STR | "true" | "false" | "(" expr ")"
//!            | "[" list "]" | IDENT ( "(" call_args ")" )?
//! call_args := (kwarg | expr) ("," (kwarg | expr))*
//! kwarg     := IDENT ":" expr
//! list      := expr ("," expr)*
//! ```
//!
//! ## Non-goals
//! - No lambdas, comprehensions, regex, member access, or arithmetic beyond
//!   `+` / `-` on numbers.
//! - No I/O, no environment lookups, no host calls. Pure data → bool.
//! - Function whitelist is intentionally narrow (see [`eval::call`]).
//!
//! Re-exports keep the public surface tight: callers reach for
//! [`parser::parse`], [`eval::eval`], and [`eval::eval_predicate`].

pub mod eval;
pub mod lexer;
pub mod parser;

pub use eval::{eval, eval_predicate, EvalEnv, EvalError, Value};
pub use lexer::{LexError, Token};
pub use parser::{parse, BinOp, Expr, ParseError, UnaryOp};
