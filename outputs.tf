output "attack_protections_id" {
  description = "Map of id values across all attack_protections, keyed the same as var.attack_protections except keys with no id are omitted"
  value       = { for k, v in auth0_attack_protection.attack_protections : k => v.id if v.id != null && length(v.id) > 0 }
}
output "attack_protections_bot_detection" {
  description = "Map of bot_detection values across all attack_protections, keyed the same as var.attack_protections except keys with no bot_detection are omitted"
  value       = { for k, v in auth0_attack_protection.attack_protections : k => one(v.bot_detection) if v.bot_detection != null && length(v.bot_detection) > 0 }
}
output "attack_protections_breached_password_detection" {
  description = "Map of breached_password_detection values across all attack_protections, keyed the same as var.attack_protections except keys with no breached_password_detection are omitted"
  value       = { for k, v in auth0_attack_protection.attack_protections : k => one(v.breached_password_detection) if v.breached_password_detection != null && length(v.breached_password_detection) > 0 }
}
output "attack_protections_brute_force_protection" {
  description = "Map of brute_force_protection values across all attack_protections, keyed the same as var.attack_protections except keys with no brute_force_protection are omitted"
  value       = { for k, v in auth0_attack_protection.attack_protections : k => one(v.brute_force_protection) if v.brute_force_protection != null && length(v.brute_force_protection) > 0 }
}
output "attack_protections_captcha" {
  description = "Map of captcha values across all attack_protections, keyed the same as var.attack_protections except keys with no captcha are omitted"
  value       = { for k, v in auth0_attack_protection.attack_protections : k => one(v.captcha) if v.captcha != null && length(v.captcha) > 0 }
  sensitive   = true
}
output "attack_protections_phone_provider_protection" {
  description = "Map of phone_provider_protection values across all attack_protections, keyed the same as var.attack_protections except keys with no phone_provider_protection are omitted"
  value       = { for k, v in auth0_attack_protection.attack_protections : k => one(v.phone_provider_protection) if v.phone_provider_protection != null && length(v.phone_provider_protection) > 0 }
}
output "attack_protections_suspicious_ip_throttling" {
  description = "Map of suspicious_ip_throttling values across all attack_protections, keyed the same as var.attack_protections except keys with no suspicious_ip_throttling are omitted"
  value       = { for k, v in auth0_attack_protection.attack_protections : k => one(v.suspicious_ip_throttling) if v.suspicious_ip_throttling != null && length(v.suspicious_ip_throttling) > 0 }
}

