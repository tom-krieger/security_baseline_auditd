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
# @example
#   class { 'security_baseline_auditd::rules::immutable':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
class security_baseline_auditd::rules::immutable (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  require 'auditd'

  if($enforce) {

    auditd::rule { '-e 2':
      order => 9999,
    }

  } else {
    if($facts['security_baseline_auditd']['immutable'] == false) {
      echo { 'auditd-mounts':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

      ::security_baseline::logging { 'auditd-immutable':
        rulenr    => 'auditd',
        rule      => 'auditd',
        desc      => 'Ensure the audit configuration is immutable (Scored)',
        level     => $log_level,
        msg       => 'Auditd configuration is not immutable.',
        rulestate => 'not compliant',
      }
    }
  }
}
