output "agent_service_account_email" {
  description = "Least-privilege IAM service account email bound to Vertex AI Agent Engine."
  value       = google_service_account.sentinel_agent_sa.email
}

output "vertex_search_datastore_id" {
  description = "Provisioned Vertex AI Search datastore ID for grounded SRE runbook retrieval."
  value       = google_discovery_engine_data_store.sre_runbooks.data_store_id
}

output "session_sql_connection_name" {
  description = "Cloud SQL PostgreSQL connection name backing DatabaseSessionService."
  value       = google_sql_database_instance.session_store.connection_name
}

output "dlp_deidentify_template_id" {
  description = "Full resource name of the Cloud DLP PII redaction template."
  value       = google_data_loss_prevention_deidentify_template.pii_scrubber.id
}

output "secret_manager_secret_ids" {
  description = "Provisioned Secret Manager secret containers injected at runtime."
  value       = [for s in google_secret_manager_secret.managed_secrets : s.secret_id]
}
