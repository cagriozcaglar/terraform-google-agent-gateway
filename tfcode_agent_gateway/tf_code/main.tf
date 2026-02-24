# The agent_gateway module provides a flexible interface for creating various types of gateways for agent-based systems on Google Cloud.
# It supports three primary patterns, selectable via the `gateway_type` variable:
# 1.  `EXTERNAL_GLOBAL`: A highly available, global gateway using a Global External HTTPS Load Balancer. It provides a static IP, managed SSL, and optional Cloud Armor protection. Ideal for agents communicating over the public internet.
# 2.  `API_GATEWAY`: A fully managed, serverless gateway using Google Cloud API Gateway. It uses an OpenAPI specification to define the API surface and is suitable for agents submitting structured data to serverless backends like Cloud Functions.
# 3.  `INTERNAL_REGIONAL_IAP`: A regional, private gateway using an Internal HTTPS Load Balancer protected by Identity-Aware Proxy (IAP). This ensures that only authenticated agents (e.g., those with a specific service account) can access internal backend services.
#
# This module encapsulates the complexity of setting up these different gateway types, allowing users to select the appropriate pattern for their architecture with a consistent interface.

# <!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
# <!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

locals {
  # Boolean flags to control resource creation based on the selected gateway type.
  is_external_global   = var.gateway_type == "EXTERNAL_GLOBAL"
  is_api_gateway       = var.gateway_type == "API_GATEWAY"
  is_internal_regional = var.gateway_type == "INTERNAL_REGIONAL_IAP"

  # Process the OpenAPI spec content, replacing a placeholder with the backend target address.
  # This is only performed when creating an API Gateway.
  processed_openapi_spec = local.is_api_gateway && var.openapi_spec_contents != null ? base64encode(replace(var.openapi_spec_contents, "$${backend_address}", var.backend_target_address)) : ""
}

# ------------------------------------------------------------------------------
# --- Resources for Global External HTTPS Load Balancer (EXTERNAL_GLOBAL)
# ------------------------------------------------------------------------------

#
# Reserve a global static IP address for the gateway.
# This ensures a stable, predictable entry point for agents.
resource "google_compute_global_address" "agent_gateway_ip" {
  # Conditionally create this resource only if the gateway type is EXTERNAL_GLOBAL.
  count = local.is_external_global ? 1 : 0

  # The GCP project ID.
  project = var.project_id
  # A unique name for the global IP address resource.
  name = "${var.name}-static-ip"
  # User-defined labels.
  labels = var.labels
}

#
# Provision a Google-managed SSL certificate for the gateway's custom domain.
# This automates SSL certificate issuance and renewal.
resource "google_compute_managed_ssl_certificate" "agent_gateway_ssl_cert" {
  # Conditionally create this resource only if the gateway type is EXTERNAL_GLOBAL.
  count = local.is_external_global ? 1 : 0

  # The GCP project ID.
  project = var.project_id
  # A unique name for the SSL certificate resource.
  name = "${var.name}-ssl-cert"

  # Configuration for the managed certificate.
  managed {
    # The list of domains this certificate will cover.
    domains = [var.gateway_domain_name]
  }
}

#
# Define a Cloud Armor security policy for WAF and DDoS protection.
# This provides a first line of defense against common web attacks.
resource "google_compute_security_policy" "agent_gateway_policy" {
  # Conditionally create this resource only if EXTERNAL_GLOBAL type is chosen and Cloud Armor is enabled.
  count = local.is_external_global && var.create_cloud_armor_policy ? 1 : 0

  # The GCP project ID.
  project = var.project_id
  # A unique name for the security policy.
  name = "${var.name}-armor-policy"
  # A description for the policy.
  description = "Basic WAF and DDoS protection for the ${var.name} agent gateway."
  # User-defined labels.
  labels = var.labels

  # A rule to deny traffic from a specified list of source IP ranges.
  rule {
    # The action to take when the match condition is met.
    action = "deny(403)"
    # The priority of the rule, lower numbers have higher precedence.
    priority = 1000
    # The condition that triggers the rule.
    match {
      # The Common Expression Language (CEL) version.
      versioned_expr = "SRC_IPS_V1"
      # Configuration for the expression.
      config {
        # The list of source IP ranges to match.
        src_ip_ranges = var.cloud_armor_source_ip_ranges_deny
      }
    }
    # A description for this specific rule.
    description = "Block traffic from known bad IP ranges."
  }

  # The default rule to allow all other traffic.
  # This rule has the lowest possible priority to ensure it's evaluated last.
  rule {
    # The action to take when the match condition is met.
    action = "allow"
    # The lowest possible priority.
    priority = 2147483647
    # The condition that triggers the rule.
    match {
      # The Common Expression Language (CEL) version.
      versioned_expr = "SRC_IPS_V1"
      # Configuration for the expression.
      config {
        # Match all source IP ranges.
        src_ip_ranges = ["*"]
      }
    }
    # A description for this specific rule.
    description = "Default allow rule for all other traffic."
  }
}

#
# Define the URL map to route all incoming requests to the primary backend service.
resource "google_compute_url_map" "agent_gateway_url_map" {
  # Conditionally create this resource only if the gateway type is EXTERNAL_GLOBAL.
  count = local.is_external_global ? 1 : 0

  # The GCP project ID.
  project = var.project_id
  # A unique name for the URL map.
  name = "${var.name}-url-map"
  # The default backend service to which traffic is routed if no host or path rules match.
  default_service = var.backend_service_id
}

#
# Create the HTTPS target proxy to terminate SSL using the managed certificate.
resource "google_compute_target_https_proxy" "agent_gateway_proxy" {
  # Conditionally create this resource only if the gateway type is EXTERNAL_GLOBAL.
  count = local.is_external_global ? 1 : 0

  # The GCP project ID.
  project = var.project_id
  # A unique name for the target HTTPS proxy.
  name = "${var.name}-https-proxy"
  # The URL map that defines the routing rules.
  url_map = google_compute_url_map.agent_gateway_url_map[0].id
  # The list of SSL certificates to use for SSL termination.
  ssl_certificates = [google_compute_managed_ssl_certificate.agent_gateway_ssl_cert[0].id]
}

#
# Create the global forwarding rule to tie the static IP address to the HTTPS proxy.
# This makes the load balancer accessible from the internet.
resource "google_compute_global_forwarding_rule" "agent_gateway_forwarding_rule" {
  # Conditionally create this resource only if the gateway type is EXTERNAL_GLOBAL.
  count = local.is_external_global ? 1 : 0

  # The GCP project ID.
  project = var.project_id
  # A unique name for the forwarding rule.
  name = "${var.name}-forwarding-rule"
  # User-defined labels.
  labels = var.labels
  # The target proxy to which traffic should be forwarded.
  target = google_compute_target_https_proxy.agent_gateway_proxy[0].id
  # The reserved global static IP address.
  ip_address = google_compute_global_address.agent_gateway_ip[0].address
  # The port on which the forwarding rule listens.
  port_range = "443"
  # The load balancing scheme, EXTERNAL for global external load balancers.
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

# ------------------------------------------------------------------------------
# --- Resources for Google Cloud API Gateway (API_GATEWAY)
# ------------------------------------------------------------------------------

#
# Define the API resource itself. This acts as a container for API configurations.
resource "google_api_gateway_api" "agent_api" {
  # Conditionally create this resource only if the gateway type is API_GATEWAY.
  count = local.is_api_gateway ? 1 : 0

  # The google-beta provider is required for this resource.
  provider = google-beta
  # The GCP project ID.
  project = var.project_id
  # The unique identifier for the API.
  api_id = var.name
  # A user-friendly name for the API.
  display_name = "${var.name} API"
  # User-defined labels.
  labels = var.labels
}

#
# Define the API configuration using an OpenAPI v2 specification.
# The spec defines paths, methods, and backend routing.
resource "google_api_gateway_api_config" "agent_api_config" {
  # Conditionally create this resource only if the gateway type is API_GATEWAY.
  count = local.is_api_gateway ? 1 : 0

  # The google-beta provider is required for this resource.
  provider = google-beta
  # The GCP project ID.
  project = var.project_id
  # The API this configuration belongs to.
  api = google_api_gateway_api.agent_api[0].api_id
  # A unique identifier for the API configuration.
  api_config_id = "${var.name}-config-v1"
  # A user-friendly name for the API configuration.
  display_name = "${var.name} Config v1"
  # User-defined labels.
  labels = var.labels

  # The OpenAPI documents that define the API.
  openapi_documents {
    # A single document for the specification.
    document {
      # A logical path for the document.
      path = "spec.yaml"
      # The base64-encoded content of the OpenAPI spec.
      contents = local.processed_openapi_spec
    }
  }

  # Ensure a new config is created before the old one is destroyed to avoid downtime.
  lifecycle {
    create_before_destroy = true
  }
}

#
# Deploy the gateway, which makes the API configuration live and accessible.
resource "google_api_gateway_gateway" "agent_gateway" {
  # Conditionally create this resource only if the gateway type is API_GATEWAY.
  count = local.is_api_gateway ? 1 : 0

  # The google-beta provider is required for this resource.
  provider = google-beta
  # The GCP project ID.
  project = var.project_id
  # The region where the gateway is deployed.
  region = var.region
  # The API configuration to deploy.
  api_config = google_api_gateway_api_config.agent_api_config[0].id
  # A unique identifier for the gateway.
  gateway_id = var.name
  # A user-friendly name for the gateway.
  display_name = "${var.name} Gateway"
  # User-defined labels.
  labels = var.labels
}

# ------------------------------------------------------------------------------
# --- Resources for Internal HTTPS Load Balancer with IAP (INTERNAL_REGIONAL_IAP)
# ------------------------------------------------------------------------------

#
# Reserve an internal IP address for the load balancer's forwarding rule.
resource "google_compute_address" "internal_ip" {
  # Conditionally create this resource only if the gateway type is INTERNAL_REGIONAL_IAP.
  count = local.is_internal_regional ? 1 : 0

  # The GCP project ID.
  project = var.project_id
  # The region for the internal IP address.
  region = var.region
  # A unique name for the address resource.
  name = "${var.name}-internal-ip"
  # User-defined labels.
  labels = var.labels
  # The subnetwork from which to allocate the IP.
  subnetwork = var.subnetwork_id
  # The type of address, INTERNAL for private IPs.
  address_type = "INTERNAL"
}

#
# Define the regional backend service and enable IAP on it.
resource "google_compute_region_backend_service" "agent_gateway_backend" {
  # Conditionally create this resource only if the gateway type is INTERNAL_REGIONAL_IAP.
  count = local.is_internal_regional ? 1 : 0

  # The GCP project ID.
  project = var.project_id
  # The region for the backend service.
  region = var.region
  # A unique name for the backend service.
  name = "${var.name}-internal-backend"
  # The load balancing scheme, INTERNAL_MANAGED for internal HTTPS LBs.
  load_balancing_scheme = "INTERNAL_MANAGED"
  # The protocol used by the backend service.
  protocol = "HTTPS"
  # The health check to monitor backend health.
  health_checks = [var.health_check_id]

  # Configuration block to enable Identity-Aware Proxy.
  iap {
    # Enable IAP for this backend service.
    enabled = true
    # The OAuth2 client ID for IAP.
    oauth2_client_id = var.iap_oauth2_client_id
    # The OAuth2 client secret for IAP.
    oauth2_client_secret = var.iap_oauth2_client_secret
  }

  # Dynamically attach backend instance groups.
  dynamic "backend" {
    # Iterate over the list of instance group URLs provided by the user.
    for_each = toset(var.backend_service_groups)
    content {
      # The URL of the instance group.
      group = backend.value
    }
  }
}

#
# Create a URL map for the internal load balancer.
resource "google_compute_region_url_map" "agent_gateway_url_map" {
  # Conditionally create this resource only if the gateway type is INTERNAL_REGIONAL_IAP.
  count = local.is_internal_regional ? 1 : 0

  # The GCP project ID.
  project = var.project_id
  # The region for the URL map.
  region = var.region
  # A unique name for the URL map.
  name = "${var.name}-internal-url-map"
  # The default backend service to route all traffic to.
  default_service = google_compute_region_backend_service.agent_gateway_backend[0].id
}

#
# Create the target HTTPS proxy for the internal load balancer.
resource "google_compute_region_target_https_proxy" "agent_gateway_proxy" {
  # Conditionally create this resource only if the gateway type is INTERNAL_REGIONAL_IAP.
  count = local.is_internal_regional ? 1 : 0

  # The GCP project ID.
  project = var.project_id
  # The region for the target proxy.
  region = var.region
  # A unique name for the target proxy.
  name = "${var.name}-internal-proxy"
  # The URL map that defines routing rules.
  url_map = google_compute_region_url_map.agent_gateway_url_map[0].id
  # The SSL certificate to use for terminating SSL.
  ssl_certificates = [var.self_managed_ssl_cert_id]
}

#
# Create the forwarding rule with an internal IP address to direct traffic to the proxy.
resource "google_compute_forwarding_rule" "agent_gateway_forwarding_rule" {
  # Conditionally create this resource only if the gateway type is INTERNAL_REGIONAL_IAP.
  count = local.is_internal_regional ? 1 : 0

  # The GCP project ID.
  project = var.project_id
  # The region for the forwarding rule.
  region = var.region
  # A unique name for the forwarding rule.
  name = "${var.name}-internal-fwd-rule"
  # User-defined labels.
  labels = var.labels
  # The VPC network this rule applies to.
  network = var.network_id
  # The subnetwork this rule applies to.
  subnetwork = var.subnetwork_id
  # The IP protocol.
  ip_protocol = "TCP"
  # The port range to forward.
  port_range = "443"
  # The load balancing scheme.
  load_balancing_scheme = "INTERNAL_MANAGED"
  # The target proxy to receive traffic.
  target = google_compute_region_target_https_proxy.agent_gateway_proxy[0].id
  # The reserved internal IP address for the rule.
  ip_address = google_compute_address.internal_ip[0].address
  # Allow global access from all regions within the same VPC.
  allow_global_access = true
}

#
# Grant the agent's service account the "IAP-secured Web App User" role.
# This allows the service account to bypass the IAP authentication challenge.
resource "google_iap_web_backend_service_iam_member" "iap_access" {
  # Conditionally create this resource only if the gateway type is INTERNAL_REGIONAL_IAP.
  count = local.is_internal_regional ? 1 : 0

  # The GCP project ID.
  project = var.project_id
  # The name of the IAP-secured backend service. The region is inferred from the backend service.
  web_backend_service = google_compute_region_backend_service.agent_gateway_backend[0].name
  # The IAM role that grants access through IAP.
  role = "roles/iap.httpsResourceAccessor"
  # The service account principal to grant the role to.
  member = "serviceAccount:${var.agent_service_account_email}"
}
