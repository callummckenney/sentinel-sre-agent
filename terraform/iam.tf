resource "google_service_account" "sentinel_agent_sa" {
  account_id   = "sentinel-sre-agent-${var.environment}"
  display_name = "Sentinel SRE ADK Agent Runtime Service Account (${var.environment})"
}

locals {
  agent_iam_roles = toset([
    "roles/aiplatform.user",
    "roles/discoveryengine.viewer",
    "roles/dlp.user",
    "roles/cloudsql.client",
    "roles/cloudtrace.agent",
    "roles/logging.logWriter",
  ])
}

resource "google_project_iam_member" "agent_least_privilege_roles" {
  for_each = local.agent_iam_roles
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.sentinel_agent_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "agent_secret_access" {
  for_each  = google_secret_manager_secret.managed_secrets
  project   = var.project_id
  secret_id = each.value.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.sentinel_agent_sa.email}"
}
