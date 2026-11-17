locals {
  required_apis = toset([
    "aiplatform.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudtrace.googleapis.com",
    "discoveryengine.googleapis.com",
    "dlp.googleapis.com",
    "logging.googleapis.com",
    "modelarmor.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "sqladmin.googleapis.com",
  ])
}

resource "google_project_service" "agent_platform_apis" {
  for_each           = local.required_apis
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# 1. Vertex AI Search DataStore for Grounded SRE Runbooks (Criterion 2.3)
resource "google_discovery_engine_data_store" "sre_runbooks" {
  location                    = "global"
  data_store_id               = "${var.datastore_id}-${var.environment}"
  display_name                = "Sentinel Verified SRE Runbooks (${var.environment})"
  industry_vertical           = "GENERIC"
  content_config              = "CONTENT_REQUIRED"
  solution_types              = ["SOLUTION_TYPE_SEARCH"]
  create_advanced_site_search = false

  depends_on = [google_project_service.agent_platform_apis]
}

# 2. Persistent Session Store: Cloud SQL PostgreSQL (Criterion 2.3)
resource "google_sql_database_instance" "session_store" {
  name                = "sentinel-sessions-${var.environment}"
  database_version    = "POSTGRES_15"
  region              = var.region
  deletion_protection = true

  settings {
    tier              = var.sql_tier
    availability_type = "REGIONAL"

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }

    ip_configuration {
      ipv4_enabled = false
      ssl_mode     = "ENCRYPTED_ONLY"
    }
  }

  depends_on = [google_project_service.agent_platform_apis]
}

resource "google_sql_database" "adk_sessions_db" {
  name     = "adk_sessions"
  instance = google_sql_database_instance.session_store.name
}

# 3. Google Cloud Secret Manager Containers — Zero Hardcoded Secrets (Criterion 5.3)
resource "google_secret_manager_secret" "managed_secrets" {
  for_each = toset([
    "sentinel-session-db-url",
    "sentinel-pagerduty-routing-key",
    "sentinel-deploy-controller-token",
  ])

  secret_id = each.value
  labels = {
    app         = "sentinel-sre-agent"
    environment = var.environment
    managed_by  = "terraform"
  }

  replication {
    auto {}
  }

  depends_on = [google_project_service.agent_platform_apis]
}

# 4. Sensitive Data Protection (Cloud DLP) PII Redaction Template (Criterion 4.4)
resource "google_data_loss_prevention_deidentify_template" "pii_scrubber" {
  parent       = "projects/${var.project_id}/locations/${var.region}"
  display_name = "Sentinel SRE Agent PII Scrubber (${var.environment})"
  description  = "Redacts emails, SSNs, phone numbers, credit cards, auth tokens, and IPs prior to logging or memory storage."

  deidentify_config {
    info_type_transformations {
      transformations {
        info_types { name = "EMAIL_ADDRESS" }
        info_types { name = "PHONE_NUMBER" }
        info_types { name = "US_SOCIAL_SECURITY_NUMBER" }
        info_types { name = "CREDIT_CARD_NUMBER" }
        info_types { name = "AUTH_TOKEN" }
        info_types { name = "IP_ADDRESS" }

        primitive_transformation {
          replace_with_info_type_config {}
        }
      }
    }
  }

  depends_on = [google_project_service.agent_platform_apis]
}

# 5. Artifact Registry for Containerized Agent Runtime / A2A Gateway
resource "google_artifact_registry_repository" "agent_images" {
  location      = var.region
  repository_id = "sentinel-sre-agent-${var.environment}"
  description   = "Container images for Sentinel SRE ADK Agent"
  format        = "DOCKER"

  depends_on = [google_project_service.agent_platform_apis]
}
