# @summary 
#    Wrapper class around all audidt checks
#
# A description of what this class does
#
# @example
#   include security_baseline_auditd::rules
class security_baseline_auditd::rules (
  Boolean $enforce   = true,
  String $message    = '',
  String $log_level  = 'info',
) {
  $classes = [
    '::security_baseline_auditd::rules::time_change',
    'security_baseline_auditd::rules::identity',
    'security_baseline_auditd::rules::system_locale',
    'security_baseline_auditd::rules::mac_policy',
    'security_baseline_auditd::rules::logins',
    'security_baseline_auditd::rules::session',
    'security_baseline_auditd::rules::perm_mod',
    'security_baseline_auditd::rules::access',
    'security_baseline_auditd::rules::privileged_commands',
  ]

  $classes.each |$class| {
    class { $class:
      enforce   => $enforce,
      message   => $message,
      log_level => $log_level,
    }
  }
}
