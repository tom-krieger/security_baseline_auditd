# @summary 
#    Ensure unsuccessful unauthorized file access attempts are collected (Scored)
#
# Monitor for unsuccessful attempts to access files. The parameters below are associated with 
# system calls that control creation ( creat ), opening ( open , openat ) and truncation 
# ( truncate , ftruncate ) of files. An audit log record will only be written if the user is a 
# non- privileged user (auid > = 1000), is not a Daemon event (auid=4294967295) and if the 
# system call returned EACCES (permission denied to the file) or EPERM (some other permanent 
# error associated with the specific system call). All audit records will be tagged with the 
# identifier "access."
#
# Rationale:
# Failed attempts to open, create or truncate files could be an indication that an individual 
# or process is trying to gain unauthorized access to the system.
#
# @example
#   class { 'security_baseline_auditd::rules::access':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
class security_baseline_auditd::rules::access (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  require 'auditd'

  if($enforce) {

    if($facts['security_baseline_auditd']['access'] == false) {
      auditd::rule { 'watch access rule 1':
        content => '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access',
      }
      auditd::rule { 'watch access rule 2':
        content => '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access',
      }
      if($facts['architecture'] == 'x86_64') {
        auditd::rule { 'watch access rule 3':
          content => '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access',
        }
        auditd::rule { 'watch access rule 4':
          content => '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access',
        }
      }
    }
  } else {
    if($facts['security_baseline_auditd']['access'] == false) {
      echo { 'auditd-access':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

      ::security_baseline::logging { 'auditd-access':
        rulenr    => 'auditd',
        rule      => 'auditd',
        desc      => 'Ensure unsuccessful unauthorized file access attempts are collected (Scored)',
        level     => $log_level,
        msg       => 'Auditd has no rule to collect unsuccessful unauthorized file access attempts.',
        rulestate => 'not compliant',
      }
    }
  }
}
