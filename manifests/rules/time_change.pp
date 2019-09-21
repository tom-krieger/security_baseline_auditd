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
#              'enforce' => true,
#   }
class security_baseline_auditd::rules::time_change (
  Boolean $enforce,
) {
  require 'auditd'

  if($enforce) {

    if($facts['security_baseline_auditd']['time-change'] == false) {
      auditd::rule { 'watch for updates to users':
        content => '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time- change',
      }
      auditd::rule { 'watch for updates to users':
        content => '-a always,exit -F arch=b32 -S clock_settime -k time-change',
      }
      auditd::rule { 'watch for updates to users':
        content => '-w /etc/localtime -p wa -k time-change',
      }

      if($facts['architecture'] == 'x86_64') {
        auditd::rule { 'watch for updates to users':
          content => '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change',
        }
        auditd::rule { 'watch for updates to users':
          content => '-a always,exit -F arch=b64 -S clock_settime -k time-change',
        }
      }
    }
  } else {
    if($facts['security_baseline_auditd']['time-change'] == false) {
    }
  }
}
