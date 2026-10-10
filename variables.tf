variable "attack_protections" {
  description = <<EOT
Map of attack_protections, attributes below
Optional:
    - bot_detection (block):
        - allowlist (optional)
        - bot_detection_level (optional)
        - challenge_password_policy (optional)
        - challenge_password_reset_policy (optional)
        - challenge_passwordless_policy (optional)
        - monitoring_mode_enabled (optional)
    - breached_password_detection (block):
        - admin_notification_frequency (optional)
        - enabled (required)
        - method (optional)
        - pre_change_password (optional, block):
            - shields (optional)
        - pre_user_registration (optional, block):
            - shields (optional)
        - shields (optional)
    - brute_force_protection (block):
        - allowlist (optional)
        - enabled (required)
        - max_attempts (optional)
        - mode (optional)
        - shields (optional)
    - captcha (block):
        - active_provider_id (optional)
        - arkose (optional, block):
            - client_subdomain (optional)
            - fail_open (optional)
            - secret (optional)
            - site_key (required)
            - verify_subdomain (optional)
        - auth_challenge (optional, block):
            - fail_open (optional)
        - friendly_captcha (optional, block):
            - secret (optional)
            - site_key (required)
        - hcaptcha (optional, block):
            - secret (optional)
            - site_key (required)
        - recaptcha_enterprise (optional, block):
            - api_key (optional)
            - project_id (required)
            - site_key (required)
        - recaptcha_v2 (optional, block):
            - secret (optional)
            - site_key (required)
    - phone_provider_protection (block):
        - type (optional)
    - suspicious_ip_throttling (block):
        - allowlist (optional)
        - enabled (required)
        - pre_login (optional, block):
            - max_attempts (optional)
            - rate (optional)
        - pre_user_registration (optional, block):
            - max_attempts (optional)
            - rate (optional)
        - shields (optional)
EOT

  type = map(object({
    bot_detection = optional(object({
      allowlist                       = optional(set(string))
      bot_detection_level             = optional(string)
      challenge_password_policy       = optional(string)
      challenge_password_reset_policy = optional(string)
      challenge_passwordless_policy   = optional(string)
      monitoring_mode_enabled         = optional(bool)
    }))
    breached_password_detection = optional(object({
      admin_notification_frequency = optional(set(string))
      enabled                      = bool
      method                       = optional(string)
      pre_change_password = optional(object({
        shields = optional(set(string))
      }))
      pre_user_registration = optional(object({
        shields = optional(set(string))
      }))
      shields = optional(set(string))
    }))
    brute_force_protection = optional(object({
      allowlist    = optional(set(string))
      enabled      = bool
      max_attempts = optional(number)
      mode         = optional(string)
      shields      = optional(set(string))
    }))
    captcha = optional(object({
      active_provider_id = optional(string)
      arkose = optional(object({
        client_subdomain = optional(string)
        fail_open        = optional(bool)
        secret           = optional(string)
        site_key         = string
        verify_subdomain = optional(string)
      }))
      auth_challenge = optional(object({
        fail_open = optional(bool)
      }))
      friendly_captcha = optional(object({
        secret   = optional(string)
        site_key = string
      }))
      hcaptcha = optional(object({
        secret   = optional(string)
        site_key = string
      }))
      recaptcha_enterprise = optional(object({
        api_key    = optional(string)
        project_id = string
        site_key   = string
      }))
      recaptcha_v2 = optional(object({
        secret   = optional(string)
        site_key = string
      }))
    }))
    phone_provider_protection = optional(object({
      type = optional(string)
    }))
    suspicious_ip_throttling = optional(object({
      allowlist = optional(set(string))
      enabled   = bool
      pre_login = optional(object({
        max_attempts = optional(number)
        rate         = optional(number)
      }))
      pre_user_registration = optional(object({
        max_attempts = optional(number)
        rate         = optional(number)
      }))
      shields = optional(set(string))
    }))
  }))
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.breached_password_detection == null || (v.breached_password_detection.shields == null || (alltrue([for x in v.breached_password_detection.shields : contains(["block", "user_notification", "admin_notification"], x)])))
      )
    ])
    error_message = "must be one of: \"block\", \"user_notification\", \"admin_notification\""
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.breached_password_detection == null || (v.breached_password_detection.admin_notification_frequency == null || (alltrue([for x in v.breached_password_detection.admin_notification_frequency : contains(["immediately", "daily", "weekly", "monthly"], x)])))
      )
    ])
    error_message = "must be one of: \"immediately\", \"daily\", \"weekly\", \"monthly\""
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.breached_password_detection == null || (v.breached_password_detection.method == null || (contains(["standard", "enhanced"], v.breached_password_detection.method)))
      )
    ])
    error_message = "must be one of: \"standard\", \"enhanced\""
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.breached_password_detection == null || (v.breached_password_detection.pre_user_registration == null || (v.breached_password_detection.pre_user_registration.shields == null || (alltrue([for x in v.breached_password_detection.pre_user_registration.shields : contains(["block", "admin_notification"], x)]))))
      )
    ])
    error_message = "must be one of: \"block\", \"admin_notification\""
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.breached_password_detection == null || (v.breached_password_detection.pre_change_password == null || (v.breached_password_detection.pre_change_password.shields == null || (alltrue([for x in v.breached_password_detection.pre_change_password.shields : contains(["block", "admin_notification"], x)]))))
      )
    ])
    error_message = "must be one of: \"block\", \"admin_notification\""
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.brute_force_protection == null || (v.brute_force_protection.shields == null || (alltrue([for x in v.brute_force_protection.shields : contains(["block", "user_notification"], x)])))
      )
    ])
    error_message = "must be one of: \"block\", \"user_notification\""
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.brute_force_protection == null || (v.brute_force_protection.mode == null || (contains(["count_per_identifier_and_ip", "count_per_identifier"], v.brute_force_protection.mode)))
      )
    ])
    error_message = "must be one of: \"count_per_identifier_and_ip\", \"count_per_identifier\""
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.brute_force_protection == null || (v.brute_force_protection.max_attempts == null || (v.brute_force_protection.max_attempts >= 0))
      )
    ])
    error_message = "must be at least 0"
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.bot_detection == null || (v.bot_detection.bot_detection_level == null || (contains(["low", "medium", "high"], v.bot_detection.bot_detection_level)))
      )
    ])
    error_message = "must be one of: \"low\", \"medium\", \"high\""
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.bot_detection == null || (v.bot_detection.challenge_password_policy == null || (contains(["never", "when_risky", "always"], v.bot_detection.challenge_password_policy)))
      )
    ])
    error_message = "must be one of: \"never\", \"when_risky\", \"always\""
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.bot_detection == null || (v.bot_detection.challenge_passwordless_policy == null || (contains(["never", "when_risky", "always"], v.bot_detection.challenge_passwordless_policy)))
      )
    ])
    error_message = "must be one of: \"never\", \"when_risky\", \"always\""
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.bot_detection == null || (v.bot_detection.challenge_password_reset_policy == null || (contains(["never", "when_risky", "always"], v.bot_detection.challenge_password_reset_policy)))
      )
    ])
    error_message = "must be one of: \"never\", \"when_risky\", \"always\""
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.phone_provider_protection == null || (v.phone_provider_protection.type == null || (contains(["exponential", "default"], v.phone_provider_protection.type)))
      )
    ])
    error_message = "must be one of: \"exponential\", \"default\""
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.captcha == null || (v.captcha.active_provider_id == null || (contains(["recaptcha_v2", "recaptcha_enterprise", "hcaptcha", "friendly_captcha", "arkose", "auth_challenge", "simple_captcha"], v.captcha.active_provider_id)))
      )
    ])
    error_message = "must be one of: \"recaptcha_v2\", \"recaptcha_enterprise\", \"hcaptcha\", \"friendly_captcha\", \"arkose\", \"auth_challenge\", \"simple_captcha\""
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.suspicious_ip_throttling == null || (v.suspicious_ip_throttling.shields == null || (alltrue([for x in v.suspicious_ip_throttling.shields : contains(["block", "admin_notification"], x)])))
      )
    ])
    error_message = "must be one of: \"block\", \"admin_notification\""
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.suspicious_ip_throttling == null || (v.suspicious_ip_throttling.pre_login == null || (v.suspicious_ip_throttling.pre_login.max_attempts == null || (v.suspicious_ip_throttling.pre_login.max_attempts >= 0)))
      )
    ])
    error_message = "must be at least 0"
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.suspicious_ip_throttling == null || (v.suspicious_ip_throttling.pre_login == null || (v.suspicious_ip_throttling.pre_login.rate == null || (v.suspicious_ip_throttling.pre_login.rate >= 0)))
      )
    ])
    error_message = "must be at least 0"
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.suspicious_ip_throttling == null || (v.suspicious_ip_throttling.pre_user_registration == null || (v.suspicious_ip_throttling.pre_user_registration.max_attempts == null || (v.suspicious_ip_throttling.pre_user_registration.max_attempts >= 0)))
      )
    ])
    error_message = "must be at least 0"
  }
  validation {
    condition = alltrue([
      for k, v in var.attack_protections : (
        v.suspicious_ip_throttling == null || (v.suspicious_ip_throttling.pre_user_registration == null || (v.suspicious_ip_throttling.pre_user_registration.rate == null || (v.suspicious_ip_throttling.pre_user_registration.rate >= 0)))
      )
    ])
    error_message = "must be at least 0"
  }
}

