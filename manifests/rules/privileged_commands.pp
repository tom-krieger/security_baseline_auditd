# @summary 
#    Ensure use of privileged commands is collected (Scored)
#
# Monitor privileged programs (those that have the setuid and/or setgid bit set on execution) to 
# determine if unprivileged users are running these commands.
#
# Rationale:
# Execution of privileged commands by non-privileged users could be an indication of someone trying 
# to gain unauthorized access to the system.
#
# @example
#   class { 'security_baseline_auditd::rules::privileged_commands':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
class security_baseline_auditd::rules::privileged_commands (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  require 'auditd'

  $logentry_default = {
    rulenr    => 'auditd-priv-cmds',
    rule      => 'auditd-priv-cmds',
    desc      => 'Ensure use of privileged commands is collected (Scored)',
  }

  if($enforce) {

    if($facts['security_baseline_auditd']['priv-cmds'] == false) {
      $facts['security_baseline_auditd']['priv-cmds-rules'].each |$part, $rules| {
        $rules.each |$rule| {
          auditd::rule { $rule:
          }
        }
      }
      $logentry_data = {
        level     => $log_level,
        msg       => 'Auditd has no rule to collect use of privileged commands.',
        rulestate => 'not compliant',
      }
    } else {
      $logentry_data = {
        level     => 'ok',
        msg       => 'Auditd has a rule to collect use of privileged commands.',
        rulestate => 'compliant',
      }
    }
  } else {
    if($facts['security_baseline_auditd']['priv-cmds'] == false) {
      echo { 'auditd-priv-cmds':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

      $logentry_data = {
        level     => $log_level,
        msg       => 'Auditd has no rule to collect use of privileged commands.',
        rulestate => 'not compliant',
      }
    }
  }

  $logentry = $logentry_default + $logentry_data
  ::security_baseline::logging { 'auditd-priv-cmds':
    * => $logentry,
  }
}
