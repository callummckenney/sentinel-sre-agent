variable "project_id" {
  description = "Target Google Cloud Project ID hosting Sentinel SRE Agent Engine & backing stores."
  type        = string
}

variable "region" {
  description = "Primary Google Cloud region for Vertex AI Agent Engine, Cloud SQL, and Cloud Run."
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Deployment environment label (dev, staging, prod)."
  type        = string
  default     = "prod"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "datastore_id" {
  description = "Vertex AI Search (Discovery Engine) DataStore ID for approved SRE runbooks."
  type        = string
  default     = "sentinel-sre-runbooks-ds"
}

variable "sql_tier" {
  description = "Machine tier for the persistent Cloud SQL PostgreSQL session database."
  type        = string
  default     = "db-custom-2-7680"
}
