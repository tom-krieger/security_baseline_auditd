# @summary 
#    Ensure events that modify the system's network environment are collected (Scored)
#
# Record changes to network environment files or system calls. The below parameters monitor the sethostname 
# (set the systems host name) or setdomainname (set the systems domainname) system calls, and write an audit 
# event on system call exit. The other parameters monitor the /etc/issue and /etc/issue.net files (messages 
# displayed pre- login), /etc/hosts (file containing host names and associated IP addresses), 
# /etc/sysconfig/network file and /etc/sysconfig/network-scripts/ directory (containing network interface 
# scripts and configurations).
#
# Rationale:
# Monitoring sethostname and setdomainname will identify potential unauthorized changes to host and domainname 
# of a system. The changing of these names could potentially break security parameters that are set based on those 
# names. The /etc/hosts file is monitored for changes in the file that can indicate an unauthorized intruder is 
# trying to change machine associations with IP addresses and trick users and processes into connecting to 
# unintended machines. Monitoring /etc/issue and /etc/issue.net is important, as intruders could put disinformation 
# into those files and trick users into providing information to the intruder. Monitoring /etc/sysconfig/network 
# and /etc/sysconfig/network-scripts/ is important as it can show if network interfaces or scripts are being modified 
# in a way that can lead to the machine becoming unavailable or compromised. All audit records will be tagged with 
# the identifier "system-locale."
#
# @example
#   class { 'security_baseline_auditd::rules::system_locale':   
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
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
          content => '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale',
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
