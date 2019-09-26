# @summary 
#    Wrapper class around all audit checks
#
# Call all classes dealing with audits rules
#
# @param enforce
#    Sets rule enforcemt. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param message
#    Message to print into the log
#
# @param log_level
#    Loglevel for the message
#
# @example
#   include security_baseline_auditd::rules
#
# @api private
class security_baseline_auditd::rules (
  Boolean $enforce   = true,
  String $message    = '',
  String $log_level  = 'info',
) {
  $classes = [
    'security_baseline_auditd::rules::time_change',
    'security_baseline_auditd::rules::identity',
    'security_baseline_auditd::rules::system_locale',
    'security_baseline_auditd::rules::mac_policy',
    'security_baseline_auditd::rules::logins',
    'security_baseline_auditd::rules::session',
    'security_baseline_auditd::rules::perm_mod',
    'security_baseline_auditd::rules::access',
    'security_baseline_auditd::rules::privileged_commands',
    'security_baseline_auditd::rules::mounts',
    'security_baseline_auditd::rules::delete',
    'security_baseline_auditd::rules::scope',
    'security_baseline_auditd::rules::actions',
    'security_baseline_auditd::rules::modules',
    'security_baseline_auditd::rules::immutable',
  ]

  $classes.each |$class| {
    class { $class:
      enforce   => $enforce,
      message   => $message,
      log_level => $log_level,
    }
  }
}
