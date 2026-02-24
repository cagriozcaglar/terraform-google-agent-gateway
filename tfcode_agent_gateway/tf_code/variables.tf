variable "agent_service_account_email" {
  description = "The email of the service account used by agents, which will be granted access via IAP. Required for INTERNAL_REGIONAL_IAP type."
  type        = string
  default     = null
}

variable "backend_service_groups" {
  description = "A list of instance group URLs to be used as backends for the internal backend service. Required for INTERNAL_REGIONAL_IAP type."
  type        = list(string)
  default     = []
}

variable "backend_service_id" {
  description = "The self-link of the external backend service to which the gateway will forward traffic. Required for EXTERNAL_GLOBAL type."
  type        = string
  default     = null
}

variable "backend_target_address" {
  description = "The backend address (e.g., a Cloud Function trigger URL) to be injected into the OpenAPI spec where '$${backend_address}' is specified. Required for API_GATEWAY type."
  type        = string
  default     = null
}

variable "cloud_armor_source_ip_ranges_deny" {
  description = "A list of IP address ranges in CIDR format to block in the Cloud Armor security policy."
  type        = list(string)
  default     = ["192.0.2.0/24"]
}

variable "create_cloud_armor_policy" {
  description = "If true, creates a basic Cloud Armor security policy with a default allow rule and a configurable deny rule."
  type        = bool
  default     = true
}

variable "gateway_domain_name" {
  description = "The domain name for which the managed SSL certificate will be provisioned. Required for EXTERNAL_GLOBAL type."
  type        = string
  default     = null
}

variable "gateway_type" {
  description = "The type of agent gateway to deploy. Must be one of: EXTERNAL_GLOBAL, API_GATEWAY, INTERNAL_REGIONAL_IAP."
  type        = string
  default     = null

  validation {
    condition     = var.gateway_type == null ? true : contains(["EXTERNAL_GLOBAL", "API_GATEWAY", "INTERNAL_REGIONAL_IAP"], var.gateway_type)
    error_message = "The gateway_type must be one of: EXTERNAL_GLOBAL, API_GATEWAY, INTERNAL_REGIONAL_IAP."
  }
}

variable "health_check_id" {
  description = "The self-link of the health check to use for the internal backend service. Required for INTERNAL_REGIONAL_IAP type."
  type        = string
  default     = null
}

variable "iap_oauth2_client_id" {
  description = "The OAuth2 client ID for IAP. Required for INTERNAL_REGIONAL_IAP type. This is created in the GCP console after configuring the OAuth consent screen."
  type        = string
  default     = null
}

variable "iap_oauth2_client_secret" {
  description = "The OAuth2 client secret for IAP. Required for INTERNAL_REGIONAL_IAP type. This is created in the GCP console after configuring the OAuth consent screen."
  type        = string
  default     = null
  sensitive   = true
}

variable "labels" {
  description = "A map of labels to apply to the created resources."
  type        = map(string)
  default     = {}
}

variable "name" {
  description = "A unique name for the agent gateway component, used as a prefix for all created resources."
  type        = string
  default     = null
}

variable "network_id" {
  description = "The self-link of the VPC network for the internal load balancer. Required for INTERNAL_REGIONAL_IAP type."
  type        = string
  default     = null
}

variable "openapi_spec_contents" {
  description = "The string content of the OpenAPI v2 specification. Use the placeholder '$${backend_address}' to have it replaced by `backend_target_address`. Required for API_GATEWAY type."
  type        = string
  default     = null
}

variable "project_id" {
  description = "The GCP project ID where the gateway and its resources will be created."
  type        = string
  default     = null
}

variable "region" {
  description = "The GCP region for regional resources. Required when gateway_type is API_GATEWAY or INTERNAL_REGIONAL_IAP."
  type        = string
  default     = null
}

variable "self_managed_ssl_cert_id" {
  description = "The self-link of the self-managed SSL certificate for the internal gateway's target proxy. Required for INTERNAL_REGIONAL_IAP type."
  type        = string
  default     = null
}

variable "subnetwork_id" {
  description = "The self-link of the subnetwork for the internal load balancer. Required for INTERNAL_REGIONAL_IAP type."
  type        = string
  default     = null
}
