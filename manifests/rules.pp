# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include security_baseline_auditd::rules
class security_baseline_auditd::rules (
  Boolen $enforce = true,
) {
  class { '::security_baseline_auditd::rules::time_change':
    enforce => $enforce,
  }
}
