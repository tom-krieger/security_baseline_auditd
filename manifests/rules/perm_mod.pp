# @summary 
#    Ensure discretionary access control permission modification events are collected (Scored)
#
# Monitor changes to file permissions, attributes, ownership and group. The parameters in this section track 
# changes for system calls that affect file permissions and attributes. The chmod , fchmod and fchmodat system 
# calls affect the permissions associated with a file. The chown , fchown , fchownat and lchown system calls 
# affect owner and group attributes on a file. The setxattr , lsetxattr , fsetxattr (set extended file attributes) 
# and removexattr , lremovexattr , fremovexattr (remove extended file attributes) control extended file attributes. 
# In all cases, an audit record will only be written for non-system user ids (auid >= 1000) and will ignore Daemon 
# events (auid = 4294967295). All audit records will be tagged with the identifier "perm_mod."
#
# Rationale:
# Monitoring for changes in file attributes could alert a system administrator to activity that could indicate 
# intruder activity or policy violation.
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
#   class { 'security_baseline_auditd::rules::perm_mod':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_auditd::rules::perm_mod (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  require 'auditd'

  $logentry_default = {
    rulenr    => '4.1.10',
    rule      => 'auditd-perm-mod',
    desc      => 'Ensure discretionary access control permission modification events are collected (Scored)',
  }

  if($facts['security_baseline_auditd']['perm-mod'] == false) {
    echo { 'auditd-perm-mod':
      message  => 'Auditd has no rule to collect discretionary access control permission modification events.',
      loglevel => $log_level,
      withpath => false,
    }

    $logentry_data = {
      level     => $log_level,
      msg       => 'Auditd has no rule to collect discretionary access control permission modification events.',
      rulestate => 'not compliant',
    }
  } else {
    $logentry_data = {
      level     => 'ok',
      msg       => 'Auditd has a rule to collect discretionary access control permission modification events.',
      rulestate => 'compliant',
    }
  }

  if($enforce) {
    auditd::rule { 'watch pem mod rule 1':
      content => '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod',
    }
    auditd::rule { 'watch perm mod rule 2':
      content => '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod',
    }
    auditd::rule { 'watch perm mod rule 3':
      content => '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod',
    }
    if($facts['architecture'] == 'x86_64') {
      auditd::rule { 'watch perm mod rule 4':
        content => '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod',
      }
      auditd::rule { 'watch perm mod rule 5':
        content => '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod',
      }
      auditd::rule { 'watch perm mod rule 6':
        content => '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod',
      }
    }
  }

  $logentry = $logentry_default + $logentry_data
  ::security_baseline::logging { 'auditd-perm-mod':
    * => $logentry,
  }
}
