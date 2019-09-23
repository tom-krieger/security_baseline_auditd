# @summary 
#    Ensure changes to system administration scope (sudoers) is collected (Scored)
#
# Monitor scope changes for system administrations. If the system has been properly configured 
# to force system administrators to log in as themselves first and then use the sudo command to 
# execute privileged commands, it is possible to monitor changes in scope. The file /etc/sudoers 
# will be written to when the file or its attributes have changed. The audit records will be tagged 
# with the identifier "scope."
# 
# Rationale:
# Changes in the /etc/sudoers file can indicate that an unauthorized change has been made to scope 
# of system administrator activity.
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
#   class { 'security_baseline_auditd::rules::scope':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_auditd::rules::scope (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  require 'auditd'

  $logentry_default = {
    rulenr    => 'auditd-scope',
    rule      => 'auditd-scope',
    desc      => 'Ensure changes to system administration scope (sudoers) is collected (Scored)',
  }

  if($facts['security_baseline_auditd']['scope'] == false) {
    echo { 'auditd-scope':
      message  => 'Auditd has no rule to collect changes to system administration scope (sudoers).',
      loglevel => $log_level,
      withpath => false,
    }

    $logentry_data = {
      level     => $log_level,
      msg       => 'Auditd has no rule to collect changes to system administration scope (sudoers).',
      rulestate => 'not compliant',
    }
  } else {
    $logentry_data = {
      level     => 'ok',
      msg       => 'Auditd has a rule to collect changes to system administration scope (sudoers).',
      rulestate => 'compliant',
    }
  }

  if($enforce) {

    if($facts['security_baseline_auditd']['scope'] == false) {
      auditd::rule { 'watch scope rule 1':
        content => '-w /etc/sudoers -p wa -k scope',
      }
      auditd::rule { 'watch scope rule 2':
        content => '-w /etc/sudoers.d/ -p wa -k scope',
      }
    }
  }

  $logentry = $logentry_default + $logentry_data
  ::security_baseline::logging { 'auditd-scope':
    * => $logentry,
  }
}
