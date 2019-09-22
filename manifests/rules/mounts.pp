# @summary 
#    Ensure successful file system mounts are collected (Scored)
#
# Monitor the use of the mount system call. The mount (and umount ) system call controls the 
# mounting and unmounting of file systems. The parameters below configure the system to create 
# an audit record when the mount system call is used by a non-privileged user
#
# Rationale:
# It is highly unusual for a non privileged user to mount file systems to the system. While tracking 
# mount commands gives the system administrator evidence that external media may have been mounted (based 
# on a review of the source of the mount and confirming it's an external media type), it does not 
# conclusively indicate that data was exported to the media. System administrators who wish to determine 
# if data were exported, would also have to track successful open , creat and truncate system calls requiring 
# write access to a file under the mount point of the external media file system. This could give a fair 
# indication that a write occurred. The only way to truly prove it, would be to track successful writes to the 
# external media. Tracking write system calls could quickly fill up the audit log and is not recommended. 
# Recommendations on configuration options to track data export to media is beyond the scope of this document.
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
#   class { 'security_baseline_auditd::rules::mounts':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_auditd::rules::mounts (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  require 'auditd'

  $logentry_default = {
    rulenr    => 'auditd-mounts',
    rule      => 'auditd-mounts',
    desc      => 'Ensure successful file system mounts are collected (Scored)',
  }

  if($enforce) {

    if($facts['security_baseline_auditd']['mounts'] == false) {
      auditd::rule { 'watch mounts rule 1':
        content => '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts',
      }
      if($facts['architecture'] == 'x86_64') {
        auditd::rule { 'watch mounts rule 2':
          content => '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts',
        }
      }
      $logentry_data = {
        level     => $log_level,
        msg       => 'Auditd has no rule to collect successful file system mounts.',
        rulestate => 'not compliant',
      }
    } else {
      $logentry_data = {
        level     => 'ok',
        msg       => 'Auditd has a rule to collect successful file system mounts.',
        rulestate => 'compliant',
      }
    }
  } else {
    if($facts['security_baseline_auditd']['mounts'] == false) {
      echo { 'auditd-mounts':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

      $logentry_data = {
        level     => $log_level,
        msg       => 'Auditd has no rule to collect successful file system mounts.',
        rulestate => 'not compliant',
      }
    }
  }

  $logentry = $logentry_default + $logentry_data
  ::security_baseline::logging { 'auditd-mounts':
    * => $logentry,
  }
}
