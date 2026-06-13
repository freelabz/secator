//! Safe expression evaluator for the workflow/scan DSL — replaces Python `eval`.
//!
//! Hand-rolled tokenizer + recursive-descent parser + tree-walking evaluator (ADR-0005).
//! Supported surface (matched against real condition strings from
//! `secator/configs/workflows/*.yaml`):
//!
//! - literals: bool, int, float, string (`'...'` or `"..."`), null, list `[a, b]`
//! - dotted member access: `opts.scanners`, `item._source`, `port.host`
//! - indexing: `targets[0]`
//! - function calls: `len(x)`, `re_match(pattern, value)`
//! - method calls: `s.lower()`, `s.upper()`, `s.startswith(x)`, `s.endswith(x)`,
//!   `s.contains(x)`
//! - operators (low → high precedence):
//!     `or` / `||`,
//!     `and` / `&&`,
//!     `not` / `!` (prefix),
//!     comparisons `==, !=, <, <=, >, >=, in, ~=`,
//!     unary `-`
//!
//! Variables are pulled from the [`Scope`]: `opts`, `item`, `targets`, and any
//! type-aliased map the engine injects (e.g. `port`, `url`).

use std::collections::BTreeMap;

// ----------------------------------------------------------------------------- Value
/// A runtime value in the expression language. Pythonic truthiness.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Value>),
    Map(BTreeMap<String, Value>),
    Null,
}

impl Value {
    /// Pythonic truthiness: empty containers / 0 / null / false are falsy.
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Int(i) => *i != 0,
            Value::Float(f) => *f != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::List(l) => !l.is_empty(),
            Value::Map(m) => !m.is_empty(),
            Value::Null => false,
        }
    }

    fn type_name(&self) -> &'static str {
        match self {
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Str(_) => "str",
            Value::List(_) => "list",
            Value::Map(_) => "map",
            Value::Null => "null",
        }
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            _ => None,
        }
    }
}

impl From<&serde_json::Value> for Value {
    fn from(v: &serde_json::Value) -> Self {
        match v {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(b) => Value::Bool(*b),
            serde_json::Value::Number(n) => n
                .as_i64()
                .map(Value::Int)
                .or_else(|| n.as_f64().map(Value::Float))
                .unwrap_or(Value::Null),
            serde_json::Value::String(s) => Value::Str(s.clone()),
            serde_json::Value::Array(a) => Value::List(a.iter().map(Value::from).collect()),
            serde_json::Value::Object(o) => {
                Value::Map(o.iter().map(|(k, v)| (k.clone(), Value::from(v))).collect())
            }
        }
    }
}

// ----------------------------------------------------------------------------- Scope
/// Variable bindings available to an expression.
#[derive(Debug, Default, Clone)]
pub struct Scope {
    pub vars: BTreeMap<String, Value>,
}
impl Scope {
    pub fn new() -> Self { Self::default() }
    pub fn with(name: &str, value: Value) -> Self {
        let mut s = Self::new();
        s.set(name, value);
        s
    }
    pub fn set(&mut self, name: &str, value: Value) -> &mut Self {
        self.vars.insert(name.to_string(), value);
        self
    }
}

// ----------------------------------------------------------------------------- Error
#[derive(Debug, Clone, PartialEq)]
pub enum EvalError {
    Parse(String),
    Runtime(String),
}
impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvalError::Parse(m) => write!(f, "parse error: {m}"),
            EvalError::Runtime(m) => write!(f, "runtime error: {m}"),
        }
    }
}
impl std::error::Error for EvalError {}

// --------------------------------------------------------------------------- Public
pub fn eval(expr: &str, scope: &Scope) -> Result<Value, EvalError> {
    let tokens = tokenize(expr)?;
    let mut parser = Parser { tokens, pos: 0 };
    let ast = parser.parse_expr()?;
    parser.expect_eof()?;
    exec(&ast, scope)
}

pub fn eval_bool(expr: &str, scope: &Scope) -> Result<bool, EvalError> {
    Ok(eval(expr, scope)?.is_truthy())
}

// ----------------------------------------------------------------------- Tokenizer
#[derive(Debug, Clone, PartialEq)]
enum Tok {
    LParen, RParen, LBracket, RBracket, Comma, Dot,
    EqEq, BangEq, Le, Ge, Lt, Gt, TildeEq,
    AndKw, OrKw, NotKw, InKw,
    Plus, Minus, Star, Slash,
    TrueKw, FalseKw, NullKw,
    Ident(String), Int(i64), Float(f64), Str(String),
    Eof,
}

fn tokenize(src: &str) -> Result<Vec<Tok>, EvalError> {
    let bytes = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => { out.push(Tok::LParen); i += 1; }
            ')' => { out.push(Tok::RParen); i += 1; }
            '[' => { out.push(Tok::LBracket); i += 1; }
            ']' => { out.push(Tok::RBracket); i += 1; }
            ',' => { out.push(Tok::Comma); i += 1; }
            '.' => { out.push(Tok::Dot); i += 1; }
            '+' => { out.push(Tok::Plus); i += 1; }
            '-' => { out.push(Tok::Minus); i += 1; }
            '*' => { out.push(Tok::Star); i += 1; }
            '/' => { out.push(Tok::Slash); i += 1; }
            '=' if peek(bytes, i + 1) == Some('=') => { out.push(Tok::EqEq); i += 2; }
            '!' if peek(bytes, i + 1) == Some('=') => { out.push(Tok::BangEq); i += 2; }
            '<' if peek(bytes, i + 1) == Some('=') => { out.push(Tok::Le); i += 2; }
            '>' if peek(bytes, i + 1) == Some('=') => { out.push(Tok::Ge); i += 2; }
            '~' if peek(bytes, i + 1) == Some('=') => { out.push(Tok::TildeEq); i += 2; }
            '<' => { out.push(Tok::Lt); i += 1; }
            '>' => { out.push(Tok::Gt); i += 1; }
            '!' => { out.push(Tok::NotKw); i += 1; }
            '&' if peek(bytes, i + 1) == Some('&') => { out.push(Tok::AndKw); i += 2; }
            '|' if peek(bytes, i + 1) == Some('|') => { out.push(Tok::OrKw); i += 2; }
            '\'' | '"' => {
                let quote = c;
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] as char != quote {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if i >= bytes.len() {
                    return Err(EvalError::Parse("unterminated string literal".into()));
                }
                let raw = &src[start..i];
                out.push(Tok::Str(unescape(raw)));
                i += 1;
            }
            d if d.is_ascii_digit() => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                    i += 1;
                }
                let lit = &src[start..i];
                if lit.contains('.') {
                    out.push(Tok::Float(
                        lit.parse()
                            .map_err(|e| EvalError::Parse(format!("bad number {lit:?}: {e}")))?,
                    ));
                } else {
                    out.push(Tok::Int(
                        lit.parse()
                            .map_err(|e| EvalError::Parse(format!("bad number {lit:?}: {e}")))?,
                    ));
                }
            }
            a if a.is_ascii_alphabetic() || a == '_' => {
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                {
                    i += 1;
                }
                let ident = &src[start..i];
                out.push(match ident {
                    "and" => Tok::AndKw,
                    "or" => Tok::OrKw,
                    "not" => Tok::NotKw,
                    "in" => Tok::InKw,
                    "true" | "True" => Tok::TrueKw,
                    "false" | "False" => Tok::FalseKw,
                    "null" | "None" => Tok::NullKw,
                    _ => Tok::Ident(ident.to_string()),
                });
            }
            other => {
                return Err(EvalError::Parse(format!(
                    "unexpected character {other:?} at byte {i}"
                )))
            }
        }
    }
    out.push(Tok::Eof);
    Ok(out)
}

fn peek(bytes: &[u8], i: usize) -> Option<char> {
    bytes.get(i).map(|&b| b as char)
}

fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('\\') => out.push('\\'),
                Some('\'') => out.push('\''),
                Some('"') => out.push('"'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

// --------------------------------------------------------------------------- AST
#[derive(Debug, Clone, PartialEq)]
enum Expr {
    Lit(Value),
    Ident(String),
    List(Vec<Expr>),
    Member(Box<Expr>, String),
    Index(Box<Expr>, Box<Expr>),
    Call(Box<Expr>, Vec<Expr>),
    Unary(UnaryOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum UnaryOp { Not, Neg }

#[derive(Debug, Clone, Copy, PartialEq)]
enum BinOp {
    Or, And, Eq, Ne, Lt, Le, Gt, Ge, In, RegexMatch,
    Add, Sub, Mul, Div,
}

// --------------------------------------------------------------------------- Parser
struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
}
impl Parser {
    fn peek(&self) -> &Tok { &self.tokens[self.pos] }
    fn advance(&mut self) -> Tok {
        let t = self.tokens[self.pos].clone();
        self.pos += 1;
        t
    }
    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == t { self.advance(); true } else { false }
    }
    fn expect(&mut self, t: &Tok) -> Result<(), EvalError> {
        if self.peek() == t { self.advance(); Ok(()) } else {
            Err(EvalError::Parse(format!("expected {t:?}, got {:?}", self.peek())))
        }
    }
    fn expect_ident(&mut self) -> Result<String, EvalError> {
        if let Tok::Ident(s) = self.peek().clone() {
            self.advance();
            Ok(s)
        } else {
            Err(EvalError::Parse(format!("expected identifier, got {:?}", self.peek())))
        }
    }
    fn expect_eof(&self) -> Result<(), EvalError> {
        if self.peek() == &Tok::Eof { Ok(()) } else {
            Err(EvalError::Parse(format!("trailing tokens: {:?}", self.peek())))
        }
    }

    fn parse_expr(&mut self) -> Result<Expr, EvalError> { self.parse_or() }

    fn parse_or(&mut self) -> Result<Expr, EvalError> {
        let mut left = self.parse_and()?;
        while self.eat(&Tok::OrKw) {
            let right = self.parse_and()?;
            left = Expr::Binary(BinOp::Or, Box::new(left), Box::new(right));
        }
        Ok(left)
    }
    fn parse_and(&mut self) -> Result<Expr, EvalError> {
        let mut left = self.parse_not()?;
        while self.eat(&Tok::AndKw) {
            let right = self.parse_not()?;
            left = Expr::Binary(BinOp::And, Box::new(left), Box::new(right));
        }
        Ok(left)
    }
    fn parse_not(&mut self) -> Result<Expr, EvalError> {
        if self.eat(&Tok::NotKw) {
            let inner = self.parse_not()?;
            return Ok(Expr::Unary(UnaryOp::Not, Box::new(inner)));
        }
        self.parse_cmp()
    }
    fn parse_cmp(&mut self) -> Result<Expr, EvalError> {
        let left = self.parse_addsub()?;
        let op = match self.peek() {
            Tok::EqEq => Some(BinOp::Eq),
            Tok::BangEq => Some(BinOp::Ne),
            Tok::Lt => Some(BinOp::Lt),
            Tok::Le => Some(BinOp::Le),
            Tok::Gt => Some(BinOp::Gt),
            Tok::Ge => Some(BinOp::Ge),
            Tok::InKw => Some(BinOp::In),
            Tok::TildeEq => Some(BinOp::RegexMatch),
            _ => None,
        };
        if let Some(op) = op {
            self.advance();
            let right = self.parse_addsub()?;
            return Ok(Expr::Binary(op, Box::new(left), Box::new(right)));
        }
        Ok(left)
    }
    fn parse_addsub(&mut self) -> Result<Expr, EvalError> {
        let mut left = self.parse_muldiv()?;
        loop {
            let op = match self.peek() {
                Tok::Plus => BinOp::Add,
                Tok::Minus => BinOp::Sub,
                _ => break,
            };
            self.advance();
            let right = self.parse_muldiv()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }
    fn parse_muldiv(&mut self) -> Result<Expr, EvalError> {
        let mut left = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Tok::Star => BinOp::Mul,
                Tok::Slash => BinOp::Div,
                _ => break,
            };
            self.advance();
            let right = self.parse_unary()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }
    fn parse_unary(&mut self) -> Result<Expr, EvalError> {
        if self.eat(&Tok::Minus) {
            return Ok(Expr::Unary(UnaryOp::Neg, Box::new(self.parse_unary()?)));
        }
        self.parse_primary()
    }
    fn parse_primary(&mut self) -> Result<Expr, EvalError> {
        let mut expr = self.parse_atom()?;
        loop {
            match self.peek() {
                Tok::Dot => {
                    self.advance();
                    let name = self.expect_ident()?;
                    expr = Expr::Member(Box::new(expr), name);
                }
                Tok::LParen => {
                    let args = self.parse_call_args()?;
                    expr = Expr::Call(Box::new(expr), args);
                }
                Tok::LBracket => {
                    self.advance();
                    let idx = self.parse_expr()?;
                    self.expect(&Tok::RBracket)?;
                    expr = Expr::Index(Box::new(expr), Box::new(idx));
                }
                _ => break,
            }
        }
        Ok(expr)
    }
    fn parse_atom(&mut self) -> Result<Expr, EvalError> {
        Ok(match self.advance() {
            Tok::TrueKw => Expr::Lit(Value::Bool(true)),
            Tok::FalseKw => Expr::Lit(Value::Bool(false)),
            Tok::NullKw => Expr::Lit(Value::Null),
            Tok::Int(i) => Expr::Lit(Value::Int(i)),
            Tok::Float(f) => Expr::Lit(Value::Float(f)),
            Tok::Str(s) => Expr::Lit(Value::Str(s)),
            Tok::Ident(name) => Expr::Ident(name),
            Tok::LParen => {
                let e = self.parse_expr()?;
                self.expect(&Tok::RParen)?;
                e
            }
            Tok::LBracket => {
                let mut items = Vec::new();
                if self.peek() != &Tok::RBracket {
                    items.push(self.parse_expr()?);
                    while self.eat(&Tok::Comma) {
                        items.push(self.parse_expr()?);
                    }
                }
                self.expect(&Tok::RBracket)?;
                Expr::List(items)
            }
            other => return Err(EvalError::Parse(format!("unexpected token in atom: {other:?}"))),
        })
    }
    fn parse_call_args(&mut self) -> Result<Vec<Expr>, EvalError> {
        self.expect(&Tok::LParen)?;
        let mut args = Vec::new();
        if self.peek() != &Tok::RParen {
            args.push(self.parse_expr()?);
            while self.eat(&Tok::Comma) {
                args.push(self.parse_expr()?);
            }
        }
        self.expect(&Tok::RParen)?;
        Ok(args)
    }
}

// ---------------------------------------------------------------------- Evaluator
fn exec(expr: &Expr, scope: &Scope) -> Result<Value, EvalError> {
    match expr {
        Expr::Lit(v) => Ok(v.clone()),
        Expr::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for e in items {
                out.push(exec(e, scope)?);
            }
            Ok(Value::List(out))
        }
        Expr::Ident(name) => scope
            .vars
            .get(name)
            .cloned()
            .ok_or_else(|| EvalError::Runtime(format!("undefined variable {name:?}"))),
        Expr::Member(target, name) => {
            let t = exec(target, scope)?;
            match t {
                Value::Map(m) => Ok(m.get(name).cloned().unwrap_or(Value::Null)),
                // Some "method" calls are handled in Call; bare `.lower` w/o `()` is invalid.
                other => Err(EvalError::Runtime(format!(
                    "cannot access member {name:?} on {}",
                    other.type_name()
                ))),
            }
        }
        Expr::Index(target, idx) => {
            let t = exec(target, scope)?;
            let i = exec(idx, scope)?;
            match (t, i) {
                (Value::List(l), Value::Int(n)) => {
                    let n = if n < 0 { l.len() as i64 + n } else { n };
                    Ok(l.get(n as usize).cloned().unwrap_or(Value::Null))
                }
                (Value::Map(m), Value::Str(k)) => Ok(m.get(&k).cloned().unwrap_or(Value::Null)),
                (Value::Str(s), Value::Int(n)) => {
                    let n = if n < 0 { s.chars().count() as i64 + n } else { n };
                    Ok(s.chars()
                        .nth(n as usize)
                        .map(|c| Value::Str(c.to_string()))
                        .unwrap_or(Value::Null))
                }
                (a, b) => Err(EvalError::Runtime(format!(
                    "cannot index {} with {}",
                    a.type_name(),
                    b.type_name()
                ))),
            }
        }
        Expr::Call(callee, args) => exec_call(callee, args, scope),
        Expr::Unary(op, inner) => {
            let v = exec(inner, scope)?;
            match op {
                UnaryOp::Not => Ok(Value::Bool(!v.is_truthy())),
                UnaryOp::Neg => match v {
                    Value::Int(i) => Ok(Value::Int(-i)),
                    Value::Float(f) => Ok(Value::Float(-f)),
                    other => Err(EvalError::Runtime(format!(
                        "cannot negate {}",
                        other.type_name()
                    ))),
                },
            }
        }
        Expr::Binary(op, l, r) => exec_binary(*op, l, r, scope),
    }
}

fn exec_call(callee: &Expr, args: &[Expr], scope: &Scope) -> Result<Value, EvalError> {
    // Method call: callee is Member(target, name).
    if let Expr::Member(target, method) = callee {
        let target_val = exec(target, scope)?;
        let arg_vals: Vec<Value> = args.iter().map(|a| exec(a, scope)).collect::<Result<_, _>>()?;
        return exec_method(&target_val, method, &arg_vals);
    }
    // Free function: callee is Ident.
    if let Expr::Ident(name) = callee {
        let arg_vals: Vec<Value> = args.iter().map(|a| exec(a, scope)).collect::<Result<_, _>>()?;
        return exec_function(name, &arg_vals);
    }
    Err(EvalError::Runtime("invalid call target".into()))
}

fn exec_method(target: &Value, method: &str, args: &[Value]) -> Result<Value, EvalError> {
    match (target, method) {
        (Value::Str(s), "lower") => Ok(Value::Str(s.to_lowercase())),
        (Value::Str(s), "upper") => Ok(Value::Str(s.to_uppercase())),
        (Value::Str(s), "strip") => Ok(Value::Str(s.trim().to_string())),
        (Value::Str(s), "startswith") => {
            let arg = args.first().and_then(as_str)
                .ok_or_else(|| EvalError::Runtime("startswith expects a string".into()))?;
            Ok(Value::Bool(s.starts_with(arg)))
        }
        (Value::Str(s), "endswith") => {
            let arg = args.first().and_then(as_str)
                .ok_or_else(|| EvalError::Runtime("endswith expects a string".into()))?;
            Ok(Value::Bool(s.ends_with(arg)))
        }
        (Value::Str(s), "contains") => {
            let arg = args.first().and_then(as_str)
                .ok_or_else(|| EvalError::Runtime("contains expects a string".into()))?;
            Ok(Value::Bool(s.contains(arg)))
        }
        (Value::List(l), "contains") => {
            let needle = args.first().ok_or_else(|| EvalError::Runtime("contains expects a value".into()))?;
            Ok(Value::Bool(l.contains(needle)))
        }
        (v, m) => Err(EvalError::Runtime(format!(
            "method {m:?} not supported on {}",
            v.type_name()
        ))),
    }
}

fn as_str(v: &Value) -> Option<&str> {
    if let Value::Str(s) = v { Some(s) } else { None }
}

fn exec_function(name: &str, args: &[Value]) -> Result<Value, EvalError> {
    match name {
        "len" => {
            let v = args.first().ok_or_else(|| EvalError::Runtime("len expects one arg".into()))?;
            Ok(Value::Int(match v {
                Value::Str(s) => s.chars().count() as i64,
                Value::List(l) => l.len() as i64,
                Value::Map(m) => m.len() as i64,
                Value::Null => 0,
                other => {
                    return Err(EvalError::Runtime(format!(
                        "len: invalid type {}",
                        other.type_name()
                    )))
                }
            }))
        }
        "re_match" => {
            let pat = args.first().and_then(as_str)
                .ok_or_else(|| EvalError::Runtime("re_match expects pattern string".into()))?;
            let val = args.get(1).and_then(as_str).unwrap_or("");
            let re = regex::Regex::new(pat)
                .map_err(|e| EvalError::Runtime(format!("invalid regex: {e}")))?;
            Ok(Value::Bool(re.is_match(val)))
        }
        "str" => Ok(Value::Str(args.first().map(value_to_string).unwrap_or_default())),
        _ => Err(EvalError::Runtime(format!("undefined function {name:?}"))),
    }
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "".to_string(),
        Value::List(l) => format!("{l:?}"),
        Value::Map(m) => format!("{m:?}"),
    }
}

fn exec_binary(op: BinOp, l: &Expr, r: &Expr, scope: &Scope) -> Result<Value, EvalError> {
    // Short-circuit boolean ops.
    match op {
        BinOp::Or => {
            let lv = exec(l, scope)?;
            return Ok(if lv.is_truthy() { lv } else { exec(r, scope)? });
        }
        BinOp::And => {
            let lv = exec(l, scope)?;
            return Ok(if !lv.is_truthy() { lv } else { exec(r, scope)? });
        }
        _ => {}
    }
    let lv = exec(l, scope)?;
    let rv = exec(r, scope)?;
    match op {
        BinOp::Eq => Ok(Value::Bool(values_equal(&lv, &rv))),
        BinOp::Ne => Ok(Value::Bool(!values_equal(&lv, &rv))),
        BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => compare(op, &lv, &rv),
        BinOp::In => Ok(Value::Bool(value_in(&lv, &rv)?)),
        BinOp::RegexMatch => {
            let pat = as_str(&rv).ok_or_else(|| EvalError::Runtime("~= rhs must be a string pattern".into()))?;
            let val = as_str(&lv).unwrap_or("");
            let re = regex::Regex::new(pat)
                .map_err(|e| EvalError::Runtime(format!("invalid regex: {e}")))?;
            Ok(Value::Bool(re.is_match(val)))
        }
        BinOp::Add => arith(op, &lv, &rv),
        BinOp::Sub => arith(op, &lv, &rv),
        BinOp::Mul => arith(op, &lv, &rv),
        BinOp::Div => arith(op, &lv, &rv),
        BinOp::Or | BinOp::And => unreachable!(),
    }
}

fn values_equal(a: &Value, b: &Value) -> bool {
    // Numeric cross-type equality (1 == 1.0 -> true).
    if let (Some(x), Some(y)) = (a.as_f64(), b.as_f64()) {
        if !matches!(a, Value::Bool(_)) && !matches!(b, Value::Bool(_)) {
            return x == y;
        }
    }
    a == b
}

fn compare(op: BinOp, a: &Value, b: &Value) -> Result<Value, EvalError> {
    if let (Some(x), Some(y)) = (a.as_f64(), b.as_f64()) {
        let ord = x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal);
        return Ok(Value::Bool(match op {
            BinOp::Lt => ord.is_lt(),
            BinOp::Le => ord.is_le(),
            BinOp::Gt => ord.is_gt(),
            BinOp::Ge => ord.is_ge(),
            _ => unreachable!(),
        }));
    }
    if let (Value::Str(x), Value::Str(y)) = (a, b) {
        return Ok(Value::Bool(match op {
            BinOp::Lt => x < y,
            BinOp::Le => x <= y,
            BinOp::Gt => x > y,
            BinOp::Ge => x >= y,
            _ => unreachable!(),
        }));
    }
    Err(EvalError::Runtime(format!(
        "cannot compare {} and {}",
        a.type_name(),
        b.type_name()
    )))
}

fn value_in(needle: &Value, haystack: &Value) -> Result<bool, EvalError> {
    match haystack {
        Value::List(l) => Ok(l.contains(needle)),
        Value::Str(s) => match needle {
            Value::Str(n) => Ok(s.contains(n.as_str())),
            _ => Err(EvalError::Runtime("`in` on string requires string lhs".into())),
        },
        Value::Map(m) => match needle {
            Value::Str(n) => Ok(m.contains_key(n)),
            _ => Err(EvalError::Runtime("`in` on map requires string lhs".into())),
        },
        Value::Null => Ok(false),
        other => Err(EvalError::Runtime(format!(
            "`in` not supported on {}",
            other.type_name()
        ))),
    }
}

fn arith(op: BinOp, a: &Value, b: &Value) -> Result<Value, EvalError> {
    // String + String concatenates.
    if op == BinOp::Add {
        if let (Value::Str(x), Value::Str(y)) = (a, b) {
            return Ok(Value::Str(format!("{x}{y}")));
        }
    }
    if let (Some(x), Some(y)) = (a.as_f64(), b.as_f64()) {
        let r = match op {
            BinOp::Add => x + y,
            BinOp::Sub => x - y,
            BinOp::Mul => x * y,
            BinOp::Div => {
                if y == 0.0 {
                    return Err(EvalError::Runtime("division by zero".into()));
                }
                x / y
            }
            _ => unreachable!(),
        };
        // If both were integers, return int.
        if matches!((a, b), (Value::Int(_), Value::Int(_))) && op != BinOp::Div {
            return Ok(Value::Int(r as i64));
        }
        return Ok(Value::Float(r));
    }
    Err(EvalError::Runtime(format!(
        "cannot apply {op:?} to {} and {}",
        a.type_name(),
        b.type_name()
    )))
}

// ----------------------------------------------------------------------- Tests
#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Value { Value::Str(v.into()) }
    fn b(v: bool) -> Value { Value::Bool(v) }
    fn i(v: i64) -> Value { Value::Int(v) }
    fn l(v: Vec<Value>) -> Value { Value::List(v) }
    fn m(v: &[(&str, Value)]) -> Value {
        Value::Map(v.iter().map(|(k, x)| (k.to_string(), x.clone())).collect())
    }
    fn check(expr: &str, scope: &Scope) -> Value {
        eval(expr, scope).unwrap_or_else(|e| panic!("eval({expr:?}) failed: {e}"))
    }

    #[test] fn literals_and_arithmetic() {
        let sc = Scope::new();
        assert_eq!(check("1 + 2 * 3", &sc), i(7));
        assert_eq!(check("(1 + 2) * 3", &sc), i(9));
        assert_eq!(check("'foo' + 'bar'", &sc), s("foobar"));
        assert_eq!(check("not false", &sc), b(true));
        assert_eq!(check("not 0", &sc), b(true));
        assert_eq!(check("not 1", &sc), b(false));
    }

    #[test] fn truthiness() {
        let sc = Scope::new();
        assert!(eval_bool("[]", &sc).unwrap() == false);
        assert!(eval_bool("[1]", &sc).unwrap());
        assert!(eval_bool("''", &sc).unwrap() == false);
        assert!(eval_bool("'a'", &sc).unwrap());
        assert!(eval_bool("0", &sc).unwrap() == false);
        assert!(eval_bool("0.0", &sc).unwrap() == false);
        assert!(eval_bool("null", &sc).unwrap() == false);
    }

    #[test] fn comparisons_and_in() {
        let mut sc = Scope::new();
        sc.set("targets", l(vec![s("a"), s("b")]));
        sc.set("opts", m(&[("scanners", l(vec![s("naabu"), s("nmap")]))]));
        assert!(eval_bool("'naabu' in opts.scanners", &sc).unwrap());
        assert!(!eval_bool("'zmap' in opts.scanners", &sc).unwrap());
        assert!(eval_bool("'a' in targets", &sc).unwrap());
        assert!(eval_bool("'sshd' in 'openssh sshd 8.0'", &sc).unwrap());
        assert!(eval_bool("1 < 2 and 2 <= 2", &sc).unwrap());
        assert!(eval_bool("'b' > 'a'", &sc).unwrap());
        assert!(eval_bool("1 == 1.0", &sc).unwrap());
    }

    #[test] fn member_access_and_methods() {
        let mut sc = Scope::new();
        sc.set("item", m(&[
            ("_source", s("gfxss")),
            ("service_name", s("openSSH")),
        ]));
        assert!(eval_bool("item._source.startswith(\"gf\")", &sc).unwrap());
        assert!(eval_bool("'ssh' in item.service_name.lower()", &sc).unwrap());
        assert_eq!(check("item.service_name.upper()", &sc), s("OPENSSH"));
    }

    #[test] fn regex_match_operator() {
        let mut sc = Scope::new();
        sc.set("item", m(&[("name", s("CVE-2024-12345"))]));
        assert!(eval_bool("item.name ~= 'CVE-\\d{4}-\\d+'", &sc).unwrap());
        assert!(!eval_bool("item.name ~= '^XYZ'", &sc).unwrap());
    }

    #[test] fn function_calls() {
        let mut sc = Scope::new();
        sc.set("opts", m(&[("scanners", l(vec![s("a"), s("b"), s("c")]))]));
        assert_eq!(check("len(opts.scanners)", &sc), i(3));
        assert_eq!(check("len('hello')", &sc), i(5));
        assert!(eval_bool("re_match('^foo', 'foobar')", &sc).unwrap());
    }

    #[test] fn short_circuit_returns_value_not_bool() {
        let sc = Scope::new();
        // Python: `a or b` returns the truthy value, not a coerced bool.
        assert_eq!(check("0 or 'default'", &sc), s("default"));
        assert_eq!(check("'x' and 'y'", &sc), s("y"));
        assert_eq!(check("'' or 0 or 'z'", &sc), s("z"));
    }

    /// Real condition strings ported from secator/configs/workflows/*.yaml.
    #[test] fn workflow_condition_strings() {
        let mut sc = Scope::new();
        sc.set("opts", m(&[
            ("scanners", l(vec![s("naabu"), s("nmap")])),
            ("passive", b(false)),
            ("nuclei", b(true)),
            ("exploiters", l(vec![s("searchsploit")])),
        ]));
        sc.set("targets", l(vec![s("h1"), s("h2")]));
        sc.set("port", m(&[
            ("port", i(22)),
            ("host", s("h1")),
            ("service_name", s("OpenSSH")),
        ]));
        sc.set("item", m(&[("_source", s("gf"))]));

        // host_recon.yaml task conditions
        assert!(eval_bool("'naabu' in opts.scanners and not opts.passive", &sc).unwrap());
        assert!(eval_bool("'nmap' in opts.scanners and not opts.passive", &sc).unwrap());
        assert!(eval_bool("not opts.passive", &sc).unwrap());
        assert!(eval_bool("opts.nuclei and not opts.passive", &sc).unwrap());
        assert!(eval_bool("'searchsploit' in opts.exploiters", &sc).unwrap());
        assert!(eval_bool("port.host in targets and opts.scanners", &sc).unwrap());
        assert!(eval_bool(
            "port.port == 22 or 'ssh' in port.service_name.lower()",
            &sc
        ).unwrap());

        // url_vuln.yaml task condition
        assert!(eval_bool("item._source.startswith(\"gf\")", &sc).unwrap());

        // Negative cases
        sc.set("opts", m(&[
            ("scanners", l(vec![s("naabu")])),
            ("passive", b(true)),
        ]));
        assert!(!eval_bool("not opts.passive", &sc).unwrap());
        assert!(!eval_bool("'nmap' in opts.scanners and not opts.passive", &sc).unwrap());
    }

    #[test] fn errors_are_descriptive() {
        let sc = Scope::new();
        let e = eval("opts.x", &sc).unwrap_err();
        assert!(format!("{e}").contains("opts"));
        let e = eval("1 +", &sc).unwrap_err();
        assert!(matches!(e, EvalError::Parse(_)));
    }
}
