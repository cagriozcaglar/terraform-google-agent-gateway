output "api_gateway_hostname" {
  description = "The default hostname of the deployed API Gateway. Populated only when gateway_type is API_GATEWAY."
  value       = local.is_api_gateway ? one(google_api_gateway_gateway.agent_gateway[*].default_hostname) : null
}

output "api_gateway_name" {
  description = "The resource name of the deployed API Gateway."
  value       = local.is_api_gateway ? one(google_api_gateway_gateway.agent_gateway[*].name) : null
}

output "cloud_armor_policy_id" {
  description = "The ID of the created Cloud Armor security policy. This policy needs to be manually attached to your backend service. Populated only when gateway_type is EXTERNAL_GLOBAL and create_cloud_armor_policy is true."
  value       = local.is_external_global && var.create_cloud_armor_policy ? one(google_compute_security_policy.agent_gateway_policy[*].id) : null
}

output "external_gateway_ip_address" {
  description = "The global static IP address of the external gateway. Populated only when gateway_type is EXTERNAL_GLOBAL."
  value       = local.is_external_global ? one(google_compute_global_address.agent_gateway_ip[*].address) : null
}

output "iap_backend_service_id" {
  description = "The ID of the IAP-enabled regional backend service created for the internal gateway. Populated only when gateway_type is INTERNAL_REGIONAL_IAP."
  value       = local.is_internal_regional ? one(google_compute_region_backend_service.agent_gateway_backend[*].id) : null
}

output "internal_gateway_ip_address" {
  description = "The internal IP address of the IAP-protected gateway. Populated only when gateway_type is INTERNAL_REGIONAL_IAP."
  value       = local.is_internal_regional ? one(google_compute_address.internal_ip[*].address) : null
}
