# @summary 
#    Ensure file deletion events by users are collected (Scored)
#
# Monitor the use of system calls associated with the deletion or renaming of files and file 
# attributes. This configuration statement sets up monitoring for the unlink (remove a file), 
# unlinkat (remove a file attribute), rename (rename a file) and renameat (rename a file attribute) 
# system calls and tags them with the identifier "delete".
#
# Rationale:
# Monitoring these calls from non-privileged users could provide a system administrator with evidence 
# that inappropriate removal of files and file attributes associated with protected files is occurring. 
# While this audit option will look at all events, system administrators will want to look for specific 
# privileged files that are being deleted or altered.
#
# @example
#   class { 'security_baseline_auditd::rules::delete':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
class security_baseline_auditd::rules::delete (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  require 'auditd'

  if($enforce) {

    if($facts['security_baseline_auditd']['delete'] == false) {
      auditd::rule { 'watch deletes rule 1':
        content => '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete',
      }
      if($facts['architecture'] == 'x86_64') {
        auditd::rule { 'watch perm mod rule 4':
          content => '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete',
        }
      }
    }
  } else {
    if($facts['security_baseline_auditd']['delete'] == false) {
      echo { 'auditd-delete':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

      ::security_baseline::logging { 'auditd-delete':
        rulenr    => 'auditd',
        rule      => 'auditd',
        desc      => 'Ensure file deletion events by users are collected (Scored)',
        level     => $log_level,
        msg       => 'Auditd has no rule to collect file deletion events by users.',
        rulestate => 'not compliant',
      }
    }
  }
}
