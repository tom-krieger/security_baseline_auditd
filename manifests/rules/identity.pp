# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include security_baseline_auditd::rules::identity
class security_baseline_auditd::rules::identity (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  require 'auditd'

  if($enforce) {

    if($facts['security_baseline_auditd']['identity'] == false) {
      auditd::rule { 'watch identity rule 1':
        content => '-w /etc/group -p wa -k identity',
      }
      auditd::rule { 'watch identity rule 2':
        content => '-w /etc/passwd -p wa -k identity',
      }
      auditd::rule { 'watch identity rule 3':
        content => '-w /etc/gshadow -p wa -k identity',
      }
      auditd::rule { 'watch identity rule 4':
        content => '-w /etc/shadow -p wa -k identity',
      }
      auditd::rule { 'watch identity rule 5':
        content => '-w /etc/security/opasswd -p wa -k identity',
      }
    }
  } else {
    if($facts['security_baseline_auditd']['identity'] == false) {
      echo { 'auditd-identity':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

      ::security_baseline::logging { 'auditd-identity':
        rulenr    => 'auditd',
        rule      => 'auditd',
        desc      => 'Ensure events that modify user/group information are collected (Scored)',
        level     => $log_level,
        msg       => 'Auditd has no rule to collect events changing identity.',
        rulestate => 'not compliant',
      }
    }
  }
}
