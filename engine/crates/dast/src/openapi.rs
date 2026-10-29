//! Penguraian spesifikasi OpenAPI 3.x / Swagger 2.0 minimal, hanya untuk menemukan endpoint yang akan
//! diuji SQL injection oleh pemeriksaan aktif (`--active`). Lingkup sengaja kecil: `paths`, method
//! get/post/put/patch (DELETE dan method lain tidak pernah dikembalikan), parameter `path`/`query`
//! sederhana, dan skema `requestBody`/`body` berupa objek datar (string/integer/number/boolean/array/
//! objek). Skema yang tidak dapat diurai dengan aman (oneOf/allOf/anyOf, bukan objek, dsb.) membuat
//! operasi itu kehilangan pengujian badan (bukan galat; path/query tetap diuji bila ada).

use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiMethod {
    Get,
    Post,
    Put,
    Patch,
}

impl ApiMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            ApiMethod::Get => "GET",
            ApiMethod::Post => "POST",
            ApiMethod::Put => "PUT",
            ApiMethod::Patch => "PATCH",
        }
    }

    fn parse(s: &str) -> Option<ApiMethod> {
        match s.to_ascii_lowercase().as_str() {
            "get" => Some(ApiMethod::Get),
            "post" => Some(ApiMethod::Post),
            "put" => Some(ApiMethod::Put),
            "patch" => Some(ApiMethod::Patch),
            // "delete" dan method lain (head, options, trace, parameters) sengaja tidak pernah dikembalikan.
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropType {
    String,
    Integer,
    Number,
    Boolean,
    Array,
    Object,
    Unknown,
}

impl PropType {
    fn from_schema_type(t: Option<&str>) -> PropType {
        match t {
            Some("string") => PropType::String,
            Some("integer") => PropType::Integer,
            Some("number") => PropType::Number,
            Some("boolean") => PropType::Boolean,
            Some("array") => PropType::Array,
            Some("object") => PropType::Object,
            _ => PropType::Unknown,
        }
    }

    /// Nilai dasar aman bila tidak ada `example`/`default` di skema.
    pub fn default_json(self) -> Value {
        match self {
            PropType::String => Value::String("test".to_string()),
            PropType::Integer => serde_json::json!(1),
            PropType::Number => serde_json::json!(1.0),
            PropType::Boolean => Value::Bool(false),
            PropType::Array => Value::Array(Vec::new()),
            PropType::Object => Value::Object(Map::new()),
            PropType::Unknown => Value::Null,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Prop {
    pub name: String,
    pub ty: PropType,
    pub required: bool,
    example: Option<Value>,
}

impl Prop {
    /// Nilai dasar: `example`/`default` bila ada (dipilih saat parse), bila tidak pakai nilai generik aman.
    pub fn value(&self) -> Value {
        self.example
            .clone()
            .unwrap_or_else(|| self.ty.default_json())
    }

    fn new(name: &str, schema: &Value, required: bool) -> Prop {
        let ty = PropType::from_schema_type(schema.get("type").and_then(Value::as_str));
        let example = schema
            .get("example")
            .cloned()
            .or_else(|| schema.get("default").cloned());
        Prop {
            name: name.to_string(),
            ty,
            required,
            example,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Operation {
    pub method: ApiMethod,
    /// Jalur mentah dari spesifikasi, mis. `/items/{id}` (relatif terhadap origin target).
    pub path: String,
    pub path_params: Vec<Prop>,
    pub query_params: Vec<Prop>,
    /// `None` bila tidak ada requestBody atau skemanya tidak bisa diurai dengan aman sebagai objek datar.
    pub body: Option<Vec<Prop>>,
}

fn parse_params(shared: &[Value], own: Option<&Vec<Value>>) -> (Vec<Prop>, Vec<Prop>) {
    let mut path_params = Vec::new();
    let mut query_params = Vec::new();
    let all = shared.iter().chain(own.into_iter().flatten());
    for p in all {
        let Some(obj) = p.as_object() else { continue };
        let Some(name) = obj.get("name").and_then(Value::as_str) else {
            continue;
        };
        let location = obj.get("in").and_then(Value::as_str).unwrap_or("");
        // OpenAPI 3: tipe di `schema`; Swagger 2: tipe langsung di level parameter.
        let schema = obj.get("schema").cloned().unwrap_or_else(|| p.clone());
        let required = obj
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(location == "path");
        let prop = Prop::new(name, &schema, required);
        match location {
            "path" => path_params.push(prop),
            "query" => query_params.push(prop),
            _ => {} // header/cookie/formData: di luar lingkup
        }
    }
    (path_params, query_params)
}

/// Skema `requestBody` (OpenAPI 3: `requestBody.content.<media>.schema`) atau parameter `in: body`
/// (Swagger 2). Hanya objek datar; `oneOf`/`allOf`/`anyOf` atau bukan objek -> `None`.
fn parse_body(op: &Map<String, Value>) -> Option<Vec<Prop>> {
    let schema = op
        .get("requestBody")
        .and_then(Value::as_object)
        .and_then(|rb| rb.get("content"))
        .and_then(Value::as_object)
        .and_then(|c| c.values().next())
        .and_then(|mt| mt.get("schema"))
        .cloned()
        .or_else(|| {
            op.get("parameters")?
                .as_array()?
                .iter()
                .find(|p| p.get("in").and_then(Value::as_str) == Some("body"))
                .and_then(|p| p.get("schema"))
                .cloned()
        })?;
    let schema = schema.as_object()?;
    if schema.contains_key("oneOf") || schema.contains_key("allOf") || schema.contains_key("anyOf")
    {
        return None;
    }
    if !matches!(
        schema.get("type").and_then(Value::as_str),
        None | Some("object")
    ) {
        return None;
    }
    let props = schema.get("properties")?.as_object()?;
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut out = Vec::new();
    for (name, pschema) in props {
        out.push(Prop::new(name, pschema, required.contains(&name.as_str())));
    }
    Some(out)
}

/// Mengurai dokumen OpenAPI/Swagger; mengembalikan daftar kosong bila `paths` tidak ada atau bukan objek
/// (tidak pernah galat: spesifikasi yang tidak dikenali dilewati, bukan menggagalkan pemindaian).
pub fn parse(doc: &Value) -> Vec<Operation> {
    let mut ops = Vec::new();
    let Some(paths) = doc.get("paths").and_then(Value::as_object) else {
        return ops;
    };
    for (path, item) in paths {
        let Some(item) = item.as_object() else {
            continue;
        };
        let shared: Vec<Value> = item
            .get("parameters")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for (mkey, mval) in item {
            if mkey == "parameters" {
                continue; // sudah ditangani sebagai `shared` di atas
            }
            let Some(method) = ApiMethod::parse(mkey) else {
                continue; // delete/head/options/trace/bidang lain: dilewati selamanya
            };
            let Some(op) = mval.as_object() else { continue };
            let own_params = op.get("parameters").and_then(Value::as_array).cloned();
            let (path_params, query_params) = parse_params(&shared, own_params.as_ref());
            let body = parse_body(op);
            ops.push(Operation {
                method,
                path: path.clone(),
                path_params,
                query_params,
                body,
            });
        }
    }
    ops
}

/// True bila `doc` ressemble sebuah dokumen OpenAPI 3.x atau Swagger 2.0 (punya kunci `openapi` atau `swagger`).
pub fn looks_like_spec(doc: &Value) -> bool {
    doc.get("openapi").and_then(Value::as_str).is_some()
        || doc.get("swagger").and_then(Value::as_str).is_some()
}

/// Jalur umum yang dicoba otomatis saat `--active` dipakai (hanya pada origin target).
pub const WELL_KNOWN_PATHS: &[&str] = &[
    "/openapi.json",
    "/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/api-docs.json",
    "/swagger/v1/swagger.json",
    "/.well-known/openapi.json",
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_openapi3_minimal() {
        let doc = json!({
            "openapi": "3.0.0",
            "paths": {
                "/items/{id}": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}
                    ],
                    "get": {
                        "parameters": [
                            {"name": "q", "in": "query", "schema": {"type": "string"}}
                        ]
                    },
                    "put": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["name"],
                                        "properties": {
                                            "name": {"type": "string"},
                                            "qty": {"type": "integer", "example": 5}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "delete": {}
                }
            }
        });
        let ops = parse(&doc);
        assert_eq!(ops.len(), 2, "{ops:?}");
        let get = ops.iter().find(|o| o.method == ApiMethod::Get).unwrap();
        assert_eq!(get.path_params.len(), 1);
        assert_eq!(get.path_params[0].name, "id");
        assert_eq!(get.query_params[0].name, "q");
        let put = ops.iter().find(|o| o.method == ApiMethod::Put).unwrap();
        let body = put.body.as_ref().unwrap();
        assert_eq!(body.len(), 2);
        let qty = body.iter().find(|p| p.name == "qty").unwrap();
        assert_eq!(qty.value(), json!(5));
        let name_prop = body.iter().find(|p| p.name == "name").unwrap();
        assert!(name_prop.required);
        assert_eq!(name_prop.value(), json!("test"));
    }

    #[test]
    fn swagger2_body_param_and_unparseable_schema_is_skipped() {
        let doc = json!({
            "swagger": "2.0",
            "paths": {
                "/users": {
                    "post": {
                        "parameters": [
                            {"name": "body", "in": "body", "schema": {
                                "type": "object",
                                "properties": {"username": {"type": "string"}}
                            }}
                        ]
                    }
                },
                "/weird": {
                    "post": {
                        "requestBody": {"content": {"application/json": {"schema": {"oneOf": []}}}}
                    }
                }
            }
        });
        let ops = parse(&doc);
        let users = ops.iter().find(|o| o.path == "/users").unwrap();
        assert_eq!(users.body.as_ref().unwrap()[0].name, "username");
        let weird = ops.iter().find(|o| o.path == "/weird").unwrap();
        assert!(weird.body.is_none());
    }

    #[test]
    fn looks_like_spec_detection() {
        assert!(looks_like_spec(&json!({"openapi": "3.0.0"})));
        assert!(looks_like_spec(&json!({"swagger": "2.0"})));
        assert!(!looks_like_spec(&json!({"hello": "world"})));
    }
}
