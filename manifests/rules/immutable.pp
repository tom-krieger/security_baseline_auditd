# @summary 
#    Ensure the audit configuration is immutable (Scored)
#
# Set system audit so that audit rules cannot be modified with auditctl . Setting the flag "-e 2" 
# forces audit to be put in immutable mode. Audit changes can only be made on system reboot.
#
# Rationale:
# In immutable mode, unauthorized users cannot execute changes to the audit system to potentially 
# hide malicious activity and then put the audit rules back. Users would most likely notice a 
# system reboot and that could alert administrators of an attempt to make unauthorized audit changes.
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
# @param level
#    Profile level
#
# @param scored
#    Indicates if a rule is scored or not
#
# @example
#   class { 'security_baseline_auditd::rules::immutable':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_auditd::rules::immutable (
  Boolean $enforce,
  String $message   = '',
  String $log_level = 'info',
  Integer $level    = 1,
  Boolean $scored   = true,
) {
  require 'auditd'

  $logentry_default = {
    rulenr    => '4.1.18',
    rule      => 'auditd-immutable',
    desc      => 'Ensure the audit configuration is immutable (Scored)',
    level     => $level,
    scored    => $scored,
  }

  if($facts['security_baseline_auditd']['immutable'] == false) {
    echo { 'auditd-immutable':
      message  => 'Auditd configuration is not immutable.',
      loglevel => $log_level,
      withpath => false,
    }
    $logentry_data = {
      log_level => $log_level,
      msg       => 'Auditd configuration is not immutable.',
      rulestate => 'not compliant',
    }
  } else {
    $logentry_data = {
      log_level => 'ok',
      msg       => 'Auditd configuration is immutable.',
      rulestate => 'compliant',
    }

  }

  if($enforce) {
    auditd::rule { '-e 2':
      order => 9999,
    }
  }

  $logentry = $logentry_default + $logentry_data
  ::security_baseline::logging { 'auditd-immutable':
    * => $logentry,
  }
}
