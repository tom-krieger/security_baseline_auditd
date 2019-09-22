# @summary 
#    Ensure session initiation information is collected (Scored)
#
# Monitor session initiation events. The parameters in this section track changes to the files 
# associated with session events. The file /var/run/utmp file tracks all currently logged in users. 
# All audit records will be tagged with the identifier "session." The /var/log/wtmp file tracks 
# logins, logouts, shutdown, and reboot events. The file /var/log/btmp keeps track of failed login 
# attempts and can be read by entering the command /usr/bin/last -f /var/log/btmp . All audit records 
# will be tagged with the identifier "logins."
#
# Rationale:
# Monitoring these files for changes could alert a system administrator to logins occurring at unusual 
# hours, which could indicate intruder activity (i.e. a user logging in at a time when they do not normally 
# log in).
#
# @example
#   class { 'security_baseline_auditd::rules::session':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
class security_baseline_auditd::rules::session (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  require 'auditd'

  if($enforce) {

    if($facts['security_baseline_auditd']['session'] == false) {
      auditd::rule { 'watch session rule 1':
        content => '-w /var/run/utmp -p wa -k session',
      }
      $logdata_entry = {
        level     => $log_level,
        msg       => 'Auditd has no rule to collect session initiation events.',
        rulestate => 'not compliant',
      }
    } else {
      $logdata_entry = {
        level     => 'ok',
        msg       => 'Auditd has a rule to collect session initiation events.',
        rulestate => 'compliant',
      }
    }
    if($facts['security_baseline_auditd']['session-logins'] == false) {
      auditd::rule { 'watch session rule 2':
        content => '-w /var/log/wtmp -p wa -k logins',
      }
      auditd::rule { 'watch session rule 3':
        content => '-w /var/log/btmp -p wa -k logins',
      }
      ::security_baseline::logging { 'auditd-session-logins':
        rulenr    => 'auditd',
        rule      => 'auditd',
        desc      => 'Ensure session initiation information is collected (Scored)',
        level     => $log_level,
        msg       => 'Auditd has no rule to collect session initiation events (logins)',
        rulestate => 'not compliant',
      }
    } else {
      ::security_baseline::logging { 'auditd-session-logins':
        rulenr    => 'auditd',
        rule      => 'auditd',
        desc      => 'Ensure session initiation information is collected (Scored)',
        level     => 'ok',
        msg       => 'Auditd has a rule to collect session initiation events (logins).',
        rulestate => 'compliant',
      }
    }
  } else {
    if($facts['security_baseline_auditd']['session'] == false) {
      echo { 'auditd-session':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

      ::security_baseline::logging { 'auditd-session':
        rulenr    => 'auditd',
        rule      => 'auditd',
        desc      => 'Ensure session initiation information is collected (Scored)',
        level     => $log_level,
        msg       => 'Auditd has no rule to collect session initiation events.',
        rulestate => 'not compliant',
      }
    }

    if($facts['security_baseline_auditd']['session-logins'] == false) {
      echo { 'auditd-session-logins':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

      ::security_baseline::logging { 'auditd-session-logins':
        rulenr    => 'auditd',
        rule      => 'auditd',
        desc      => 'Ensure session initiation information is collected (Scored)',
        level     => $log_level,
        msg       => 'Auditd has no rule to collect session initiation events (logins).',
        rulestate => 'not compliant',
      }
    }
  }
}
