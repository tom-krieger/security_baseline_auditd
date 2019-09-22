# @summary 
#    Ensure events that modify the system's Mandatory Access Controls are collected (Scored)
#
# Monitor SELinux mandatory access controls. The parameters below monitor any write access (potential additional, 
# deletion or modification of files in the directory) or attribute changes to the /etc/selinux or directory.
#
# Rationale:
# Changes to files in these directories could indicate that an unauthorized user is attempting to modify access 
# controls and change security contexts, leading to a compromise of the system.
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
#   class { 'security_baseline_auditd::rules::mac_policy':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_auditd::rules::mac_policy (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  require 'auditd'

  $logentry_default = {
    rulenr    => 'auditd-mac-policy',
    rule      => 'auditd-mac-policy',
    desc      => 'Ensure events that modify the system\'s Mandatory Access Controls are collected (Scored)',
  }

  if($enforce) {

    if($facts['security_baseline_auditd']['mac-policy'] == false) {
      auditd::rule { 'mac policy rule 1':
        content => '-w /etc/selinux/ -p wa -k MAC-policy',
      }
      auditd::rule { 'mac policy rule 2':
        content => '-w /usr/share/selinux/ -p wa -k MAC-policy',
      }
      $logentry_data = {
        level     => $log_level,
        msg       => 'Auditd has no rule to collect events changing mandatory access controls.',
        rulestate => 'not compliant',
      }
    } else {
      $logentry_data = {
        level     => 'ok',
        msg       => 'Auditd has a rule to collect events changing mandatory access controls.',
        rulestate => 'compliant',
      }
    }
  } else {
    if($facts['security_baseline_auditd']['mac-policy'] == false) {
      echo { 'auditd-mac-policy':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

      $logentry_data = {
        level     => $log_level,
        msg       => 'Auditd has no rule to collect events changing mandatory access controls.',
        rulestate => 'not compliant',
      }
    }
  }

  $logentry = $logentry_default + $logentry_data
  ::security_baseline::logging { 'auditd-mac-policy':
    * => $logentry,
  }
}
