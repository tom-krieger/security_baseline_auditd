# @summary A short summary of the purpose of this class
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
  class { '::security_baseline_auditd::rules::time_change':
    enforce   => $enforce,
    message   => $message,
    log_level => $log_level,
  }
}
