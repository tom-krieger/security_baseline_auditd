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
#   class { 'security_baseline_auditd::rules::session':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_auditd::rules::session (
  Boolean $enforce,
  String $message   = '',
  String $log_level = 'info',
  Integer $level    = 1,
  Boolean $scored   = true,
) {
  require 'auditd'

  $session_default = {
    rulenr    => '4.1.9.1',
    rule      => 'auditd',
    desc      => 'Ensure session initiation information is collected (Scored)',
    level     => $level,
    scored    => $scored,
  }
  $logins_default = {
    rulenr    => '4.1.9.2',
    rule      => 'auditd',
    desc      => 'Ensure session initiation information is collected for logins (Scored)',
    level     => $level,
    scored    => $scored,
  }

  if($facts['security_baseline_auditd']['session'] == false) {
    echo { 'auditd-session':
      message  => 'Auditd has no rule to collect session initiation events.',
      loglevel => $log_level,
      withpath => false,
    }
    $session_entry = {
      log_level => $log_level,
      msg       => 'Auditd has no rule to collect session initiation events.',
      rulestate => 'not compliant',
    }
  } else {
    $session_entry = {
      log_level => 'ok',
      msg       => 'Auditd has a rule to collect session initiation events.',
      rulestate => 'compliant',
    }
  }
  if($facts['security_baseline_auditd']['session-logins'] == false) {
    echo { 'auditd-session-logins':
      message  => 'Auditd has no rule to collect session initiation events (logins)',
      loglevel => $log_level,
      withpath => false,
    }

    $logins_entry = {
      log_level => $log_level,
      msg       => 'Auditd has no rule to collect session initiation events (logins)',
      rulestate => 'not compliant',
    }
  } else {
    $logins_entry = {
      log_level => 'ok',
      msg       => 'Auditd has a rule to collect session initiation events (logins)',
      rulestate => 'compliant',
    }
  }

  if($enforce) {
    auditd::rule { 'watch session rule 1':
      content => '-w /var/run/utmp -p wa -k session',
    }
    auditd::rule { 'watch session rule 2':
      content => '-w /var/log/wtmp -p wa -k logins',
    }
    auditd::rule { 'watch session rule 3':
      content => '-w /var/log/btmp -p wa -k logins',
    }
  }

  $logins = $logins_default + $logins_entry
  ::security_baseline::logging { 'auditd-session-logins':
    * => $logins,
  }

  $session = $session_default + $session_entry
  ::security_baseline::logging { 'auditd-session':
    * => $session,
  }

}
