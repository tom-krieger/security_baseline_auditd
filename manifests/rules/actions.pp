# @summary 
#    Ensure system administrator actions (sudolog) are collected (Scored)
#
# Monitor the sudo log file. If the system has been properly configured to disable the use 
# of the su command and force all administrators to have to log in first and then use sudo 
# to execute privileged commands, then all administrator commands will be logged to /var/log/sudo.log. 
# Any time a command is executed, an audit event will be triggered as the /var/log/sudo.log file will 
# be opened for write and the executed administration command will be written to the log.
#
# Rationale:
# Changes in /var/log/sudo.log indicate that an administrator has executed a command or the log file 
# itself has been tampered with. Administrators will want to correlate the events written to the audit 
# trail with the records written to /var/log/sudo.log to verify if unauthorized commands have been executed.
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
#   class { 'security_baseline_auditd::rules::actions':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_auditd::rules::actions (
  Boolean $enforce,
  String $message   = '',
  String $log_level = 'info',
  Integer $level    = 1,
  Boolean $scored   = true,
) {
  require 'auditd'

  $logentry_default = {
    rulenr    => '4.1.16',
    rule      => 'auditd-actions',
    desc      => 'Ensure system administrator actions (sudolog) are collected (Scored)',
    level     => $level,
    scored    => $scored,
  }

  if($facts['security_baseline_auditd']['actions'] == false) {
    echo { 'auditd-actions':
      message  => 'Auditd has no rule to collect system administrator actions (sudolog).',
      loglevel => $log_level,
      withpath => false,
    }

    $logentry_data = {
      log_level => $log_level,
      msg       => 'Auditd has no rule to collect system administrator actions (sudolog).',
      rulestate => 'not compliant',
    }
  } else {
    $logentry_data = {
      log_level => 'ok',
      msg       => 'Auditd has a rule to collect system administrator actions (sudolog).',
      rulestate => 'compliant',
    }
  }

  if($enforce) {
    auditd::rule { 'watch admin actions rule 1':
      content => '-w /var/log/sudo.log -p wa -k actions',
    }
  }

  $logentry = $logentry_default + $logentry_data
  ::security_baseline::logging { 'auditd-actions':
    * => $logentry,
  }
}
