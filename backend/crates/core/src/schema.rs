//! JSON Schema helpers shared by MCP-facing DTOs.

use schemars::{Schema, SchemaGenerator};
use serde_json::{Value, json};

pub fn json_value_schema(_: &mut SchemaGenerator) -> Schema {
    schema_from_value(json_value_schema_value())
}

pub fn optional_json_value_schema(_: &mut SchemaGenerator) -> Schema {
    schema_from_value(json!({
        "anyOf": [
            json_value_schema_value(),
            { "type": "null" }
        ]
    }))
}

pub fn json_value_array_schema(_: &mut SchemaGenerator) -> Schema {
    schema_from_value(json!({
        "type": "array",
        "items": json_value_schema_value()
    }))
}

pub fn json_object_array_schema(_: &mut SchemaGenerator) -> Schema {
    schema_from_value(json!({
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": json_value_schema_value()
        }
    }))
}

pub fn json_value_columns_schema(_: &mut SchemaGenerator) -> Schema {
    schema_from_value(json!({
        "type": "object",
        "additionalProperties": {
            "type": "array",
            "items": json_value_schema_value()
        }
    }))
}

fn json_value_schema_value() -> Value {
    json!({
        "anyOf": [
            { "type": "object", "additionalProperties": {} },
            { "type": "array", "items": {} },
            { "type": "string" },
            { "type": "number" },
            { "type": "boolean" },
            { "type": "null" }
        ]
    })
}

fn schema_from_value(value: Value) -> Schema {
    Schema::try_from(value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn json_schema_helpers_do_not_emit_boolean_schema_nodes() -> Result<(), String> {
        for schema in [
            json_value_schema,
            optional_json_value_schema,
            json_value_array_schema,
            json_object_array_schema,
            json_value_columns_schema,
        ] {
            let value = serde_json::to_value(schema(
                &mut schemars::generate::SchemaSettings::draft2020_12().into_generator(),
            ))
            .map_err(|error| error.to_string())?;
            assert_no_boolean_schema(&value, "$")?;
        }
        Ok(())
    }

    fn assert_no_boolean_schema(value: &Value, path: &str) -> Result<(), String> {
        match value {
            Value::Bool(_) => Err(format!("boolean schema at {path}")),
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    assert_no_boolean_schema(item, &format!("{path}[{index}]"))?;
                }
                Ok(())
            }
            Value::Object(map) => {
                for (key, item) in map {
                    assert_no_boolean_schema(item, &format!("{path}.{key}"))?;
                }
                Ok(())
            }
            Value::Null | Value::Number(_) | Value::String(_) => Ok(()),
        }
    }
}
