-- Allow the runtime role to power the authenticated read-only REST dashboard APIs.

GRANT SELECT ON api_call_history TO opsgate_app;
GRANT SELECT ON sql_query_history TO opsgate_app;
GRANT SELECT ON audit_logs TO opsgate_app;
