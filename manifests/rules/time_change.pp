# @summary 
#    Ensure events that modify date and time information are collected (Scored)
#
# Capture events where the system date and/or time has been modified. The parameters in this section are set to 
# determine if the adjtimex (tune kernel clock), settimeofday (Set time, using timeval and timezone structures) 
# stime (using seconds since 1/1/1970) or clock_settime (allows for the setting of several internal clocks and 
# timers) system calls have been executed and always write an audit record to the /var/log/audit.log file upon 
# exit, tagging the records with the identifier "time-change"
#
# Rationale:
# Unexpected changes in system date and/or time could be a sign of malicious activity on the system.
#
# @example
#   class { 'security_baseline_auditd::rules::time_change':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
class security_baseline_auditd::rules::time_change (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  require 'auditd'

  if($enforce) {

    if($facts['security_baseline_auditd']['time-change'] == false) {
      auditd::rule { 'watch for date-time-change rule 1':
        content => '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time- change',
      }
      auditd::rule { 'watch for date-time-change rule 2':
        content => '-a always,exit -F arch=b32 -S clock_settime -k time-change',
      }
      auditd::rule { 'watch for date-time-change rule 3':
        content => '-w /etc/localtime -p wa -k time-change',
      }

      if($facts['architecture'] == 'x86_64') {
        auditd::rule { 'watch for date-time-change rule 4':
          content => '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change',
        }
        auditd::rule { 'wwatch for date-time-change rule 5':
          content => '-a always,exit -F arch=b64 -S clock_settime -k time-change',
        }
      }
    }
  } else {
    if($facts['security_baseline_auditd']['time-change'] == false) {
      echo { 'auditd-time-change':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

      ::security_baseline::logging { 'auditd-time-change':
        rulenr    => 'auditd',
        rule      => 'auditd',
        desc      => 'Ensure events that modify date and time information are collected (Scored)',
        level     => $log_level,
        msg       => 'Auditd has no rule to collect events changing date and time.',
        rulestate => 'not compliant',
      }
    }
  }
}
