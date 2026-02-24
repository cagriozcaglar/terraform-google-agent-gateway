terraform {
  # This module requires Terraform version 1.0 or newer.
  required_version = ">= 1.0"

  # This module uses the Google Provider for managing Google Cloud resources.
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.34.0"
    }
    # The google-beta provider is required for Google API Gateway resources.
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 4.34.0"
    }
  }
}
