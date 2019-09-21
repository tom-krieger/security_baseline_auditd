# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include security_baseline_auditd::rules::system_locale
class security_baseline_auditd::rules::system_locale (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  require 'auditd'

  if($enforce) {

    if($facts['security_baseline_auditd']['system-locale'] == false) {
      auditd::rule { 'watch network environment rule 1':
        content => '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale',
      }
      auditd::rule { 'watch network environment rule 2':
        content => '-w /etc/issue -p wa -k system-locale',
      }
      auditd::rule { 'watch network environment rule 3':
        content => '-w /etc/issue.net -p wa -k system-locale',
      }
      auditd::rule { 'watch network environment rule 4':
        content => '-w /etc/hosts -p wa -k system-locale',
      }
      auditd::rule { 'watch network environment rule 5':
        content => '-w /etc/sysconfig/network -p wa -k system-locale',
      }
      auditd::rule { 'watch network environment rule 6':
        content => '-w /etc/sysconfig/network-scripts/ -p wa -k system-locale',
      }
      if($facts['architecture'] == 'x86_64') {
        auditd::rule { 'watch network environment rule 7':
          content => ' -a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale',
        }
      }
    }
  } else {
    if($facts['security_baseline_auditd']['system-locale'] == false) {
      echo { 'auditd-identity':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

      ::security_baseline::logging { 'auditd-identity':
        rulenr    => 'auditd',
        rule      => 'auditd',
        desc      => 'Ensure events that modify the system\'s network environment are collected (Scored)',
        level     => $log_level,
        msg       => 'Auditd has no rule to collect events modifying network environment.',
        rulestate => 'not compliant',
      }
    }
  }
}
