//! Taint ringan dalam satu fungsi (lihat TRD, "Mesin SAST dan taint ringan").
//!
//! Analisis tidak peka-urutan dan tidak melacak panggilan antar-fungsi atau antar-file.
//! Sebuah ekspresi tercemar bila memuat superglobal pengguna, atau variabel yang di lingkup
//! fungsi yang sama mendapat nilai dari ekspresi tercemar. Fungsi pembersih yang terdaftar di
//! template dan cast `(int)`/`(float)` menghentikan pencemaran.

use std::collections::HashMap;

use tree_sitter::Node;

const SUPERGLOBALS: &[&str] = &[
    "$_GET",
    "$_POST",
    "$_REQUEST",
    "$_COOKIE",
    "$_FILES",
    "$_SERVER",
];

/// Batas iterasi perhitungan berulang agar selalu berhenti.
const MAX_ROUNDS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Taint {
    Clean,
    /// Variabel diberi nilai lebih dari sekali dan sebagian tidak tercemar.
    Ambiguous,
    Tainted,
}

fn text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or_default()
}

fn is_scope_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "function_definition"
            | "method_declaration"
            | "anonymous_function"
            | "anonymous_function_creation_expression"
            | "arrow_function"
    )
}

/// Lingkup fungsi terdekat yang membungkus `node`, atau akar program.
fn enclosing_scope(node: Node) -> Node {
    let mut cur = node;
    while let Some(parent) = cur.parent() {
        if is_scope_boundary(parent.kind()) || parent.kind() == "program" {
            return parent;
        }
        cur = parent;
    }
    cur
}

fn contains_variable(node: Node, src: &[u8], name: &str) -> bool {
    if node.kind() == "variable_name" {
        return text(node, src) == name;
    }
    let mut cursor = node.walk();
    let found = node
        .children(&mut cursor)
        .any(|c| contains_variable(c, src, name));
    found
}

#[derive(Default)]
struct Assignments<'t> {
    /// `$v = ...`
    plain: Vec<Node<'t>>,
    /// `$v .= ...` dan penugasan yang memakai `$v` itu sendiri di sisi kanan.
    accumulating: Vec<Node<'t>>,
}

fn collect_assignments<'t>(
    node: Node<'t>,
    src: &[u8],
    is_root: bool,
    out: &mut HashMap<String, Assignments<'t>>,
) {
    if !is_root && is_scope_boundary(node.kind()) {
        return;
    }
    let kind = node.kind();
    if kind == "assignment_expression" || kind == "augmented_assignment_expression" {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            if left.kind() == "variable_name" {
                let name = text(left, src).to_string();
                let entry = out.entry(name.clone()).or_default();
                if kind == "augmented_assignment_expression" || contains_variable(right, src, &name)
                {
                    entry.accumulating.push(right);
                } else {
                    entry.plain.push(right);
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_assignments(child, src, false, out);
    }
}

fn callee_name<'a>(node: Node, src: &'a [u8]) -> Option<&'a str> {
    let field = match node.kind() {
        "function_call_expression" => "function",
        "member_call_expression" | "nullsafe_member_call_expression" | "scoped_call_expression" => {
            "name"
        }
        _ => return None,
    };
    node.child_by_field_name(field).map(|n| text(n, src))
}

fn expr_taint(
    node: Node,
    src: &[u8],
    states: &HashMap<String, Taint>,
    sanitizers: &[String],
) -> Taint {
    match node.kind() {
        "variable_name" => {
            let name = text(node, src);
            if SUPERGLOBALS.contains(&name) {
                Taint::Tainted
            } else {
                states.get(name).copied().unwrap_or(Taint::Clean)
            }
        }
        "function_call_expression"
        | "member_call_expression"
        | "nullsafe_member_call_expression"
        | "scoped_call_expression" => {
            let sanitized = callee_name(node, src)
                .is_some_and(|n| sanitizers.iter().any(|s| s.eq_ignore_ascii_case(n)));
            if sanitized {
                return Taint::Clean;
            }
            children_taint(node, src, states, sanitizers)
        }
        "cast_expression" => {
            let numeric = node
                .child_by_field_name("type")
                .map(|t| text(t, src).trim().to_ascii_lowercase())
                .is_some_and(|t| matches!(t.as_str(), "int" | "integer" | "float" | "double"));
            if numeric {
                Taint::Clean
            } else {
                children_taint(node, src, states, sanitizers)
            }
        }
        _ => children_taint(node, src, states, sanitizers),
    }
}

fn children_taint(
    node: Node,
    src: &[u8],
    states: &HashMap<String, Taint>,
    sanitizers: &[String],
) -> Taint {
    let mut cursor = node.walk();
    let mut result = Taint::Clean;
    for child in node.children(&mut cursor) {
        result = result.max(expr_taint(child, src, states, sanitizers));
        if result == Taint::Tainted {
            break;
        }
    }
    result
}

fn variable_state(
    a: &Assignments,
    src: &[u8],
    states: &HashMap<String, Taint>,
    sanitizers: &[String],
) -> Taint {
    let plain: Vec<Taint> = a
        .plain
        .iter()
        .map(|n| expr_taint(*n, src, states, sanitizers))
        .collect();
    let tainted = plain.iter().filter(|t| **t == Taint::Tainted).count();
    let clean = plain.iter().filter(|t| **t == Taint::Clean).count();
    let plain_state = if plain.is_empty() {
        Taint::Clean
    } else if clean == 0 && tainted > 0 {
        Taint::Tainted
    } else if clean == plain.len() {
        Taint::Clean
    } else {
        Taint::Ambiguous
    };
    let accumulating_state = a
        .accumulating
        .iter()
        .map(|n| expr_taint(*n, src, states, sanitizers))
        .max()
        .unwrap_or(Taint::Clean);
    plain_state.max(accumulating_state)
}

/// Menilai apakah `node` tercemar di lingkup fungsinya, dengan pembersih milik satu template.
pub fn evaluate(node: Node, src: &[u8], sanitizers: &[String]) -> Taint {
    let scope = enclosing_scope(node);
    let mut assignments = HashMap::new();
    collect_assignments(scope, src, true, &mut assignments);

    let mut states: HashMap<String, Taint> = HashMap::new();
    for _ in 0..MAX_ROUNDS {
        let mut next = HashMap::with_capacity(assignments.len());
        for (name, a) in &assignments {
            let state = variable_state(a, src, &states, sanitizers);
            if state != Taint::Clean {
                next.insert(name.clone(), state);
            }
        }
        if next == states {
            break;
        }
        states = next;
    }
    expr_taint(node, src, &states, sanitizers)
}
