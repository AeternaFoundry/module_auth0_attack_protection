resource "auth0_attack_protection" "attack_protections" {
  for_each = var.attack_protections


  dynamic "bot_detection" {
    for_each = each.value.bot_detection != null ? [each.value.bot_detection] : []
    content {
      allowlist                       = bot_detection.value.allowlist
      bot_detection_level             = bot_detection.value.bot_detection_level
      challenge_password_policy       = bot_detection.value.challenge_password_policy
      challenge_password_reset_policy = bot_detection.value.challenge_password_reset_policy
      challenge_passwordless_policy   = bot_detection.value.challenge_passwordless_policy
      monitoring_mode_enabled         = bot_detection.value.monitoring_mode_enabled
    }
  }

  dynamic "breached_password_detection" {
    for_each = each.value.breached_password_detection != null ? [each.value.breached_password_detection] : []
    content {
      admin_notification_frequency = breached_password_detection.value.admin_notification_frequency
      enabled                      = breached_password_detection.value.enabled
      method                       = breached_password_detection.value.method
      dynamic "pre_change_password" {
        for_each = breached_password_detection.value.pre_change_password != null ? [breached_password_detection.value.pre_change_password] : []
        content {
          shields = pre_change_password.value.shields
        }
      }
      dynamic "pre_user_registration" {
        for_each = breached_password_detection.value.pre_user_registration != null ? [breached_password_detection.value.pre_user_registration] : []
        content {
          shields = pre_user_registration.value.shields
        }
      }
      shields = breached_password_detection.value.shields
    }
  }

  dynamic "brute_force_protection" {
    for_each = each.value.brute_force_protection != null ? [each.value.brute_force_protection] : []
    content {
      allowlist    = brute_force_protection.value.allowlist
      enabled      = brute_force_protection.value.enabled
      max_attempts = brute_force_protection.value.max_attempts
      mode         = brute_force_protection.value.mode
      shields      = brute_force_protection.value.shields
    }
  }

  dynamic "captcha" {
    for_each = each.value.captcha != null ? [each.value.captcha] : []
    content {
      active_provider_id = captcha.value.active_provider_id
      dynamic "arkose" {
        for_each = captcha.value.arkose != null ? [captcha.value.arkose] : []
        content {
          client_subdomain = arkose.value.client_subdomain
          fail_open        = arkose.value.fail_open
          secret           = arkose.value.secret
          site_key         = arkose.value.site_key
          verify_subdomain = arkose.value.verify_subdomain
        }
      }
      dynamic "auth_challenge" {
        for_each = captcha.value.auth_challenge != null ? [captcha.value.auth_challenge] : []
        content {
          fail_open = auth_challenge.value.fail_open
        }
      }
      dynamic "friendly_captcha" {
        for_each = captcha.value.friendly_captcha != null ? [captcha.value.friendly_captcha] : []
        content {
          secret   = friendly_captcha.value.secret
          site_key = friendly_captcha.value.site_key
        }
      }
      dynamic "hcaptcha" {
        for_each = captcha.value.hcaptcha != null ? [captcha.value.hcaptcha] : []
        content {
          secret   = hcaptcha.value.secret
          site_key = hcaptcha.value.site_key
        }
      }
      dynamic "recaptcha_enterprise" {
        for_each = captcha.value.recaptcha_enterprise != null ? [captcha.value.recaptcha_enterprise] : []
        content {
          api_key    = recaptcha_enterprise.value.api_key
          project_id = recaptcha_enterprise.value.project_id
          site_key   = recaptcha_enterprise.value.site_key
        }
      }
      dynamic "recaptcha_v2" {
        for_each = captcha.value.recaptcha_v2 != null ? [captcha.value.recaptcha_v2] : []
        content {
          secret   = recaptcha_v2.value.secret
          site_key = recaptcha_v2.value.site_key
        }
      }
    }
  }

  dynamic "phone_provider_protection" {
    for_each = each.value.phone_provider_protection != null ? [each.value.phone_provider_protection] : []
    content {
      type = phone_provider_protection.value.type
    }
  }

  dynamic "suspicious_ip_throttling" {
    for_each = each.value.suspicious_ip_throttling != null ? [each.value.suspicious_ip_throttling] : []
    content {
      allowlist = suspicious_ip_throttling.value.allowlist
      enabled   = suspicious_ip_throttling.value.enabled
      dynamic "pre_login" {
        for_each = suspicious_ip_throttling.value.pre_login != null ? [suspicious_ip_throttling.value.pre_login] : []
        content {
          max_attempts = pre_login.value.max_attempts
          rate         = pre_login.value.rate
        }
      }
      dynamic "pre_user_registration" {
        for_each = suspicious_ip_throttling.value.pre_user_registration != null ? [suspicious_ip_throttling.value.pre_user_registration] : []
        content {
          max_attempts = pre_user_registration.value.max_attempts
          rate         = pre_user_registration.value.rate
        }
      }
      shields = suspicious_ip_throttling.value.shields
    }
  }
}

