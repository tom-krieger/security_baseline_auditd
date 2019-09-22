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
# @example
#   class { 'security_baseline_auditd::rules::actions':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
class security_baseline_auditd::rules::actions (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  require 'auditd'

  if($enforce) {

    if($facts['security_baseline_auditd']['actions'] == false) {
      auditd::rule { 'watch admin actions rule 1':
        content => '-w /var/log/sudo.log -p wa -k actions',
      }
    }
  } else {
    if($facts['security_baseline_auditd']['actions'] == false) {
      echo { 'auditd-actions':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

      ::security_baseline::logging { 'auditd-actions':
        rulenr    => 'auditd',
        rule      => 'auditd',
        desc      => 'Ensure system administrator actions (sudolog) are collected (Scored)',
        level     => $log_level,
        msg       => 'Auditd has no rule to collect system administrator actions (sudolog).',
        rulestate => 'not compliant',
      }
    }
  }
}
