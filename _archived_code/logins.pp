# @summary 
#    Ensure login and logout events are collected (Scored)
#
# Monitor login and logout events. The parameters below track changes to files associated with login/logout events. 
# The file /var/log/lastlog maintain records of the last time a user successfully logged in. The /var/run/failock 
# directory maintains records of login failures via the pam_faillock module.
# 
# Rationale:
# Monitoring login/logout events could provide a system administrator with information associated with brute force 
# attacks against user logins.
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
#   class { 'security_baseline_auditd::rules::logins':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_auditd::rules::logins (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  require 'auditd'

  $logentry_default = {
    rulenr    => '4.1.8',
    rule      => 'auditd-logins',
    desc      => 'Ensure login and logout events are collected (Scored)',
  }

  if($facts['security_baseline_auditd']['logins'] == false) {
    echo { 'auditd-logins':
      message  => 'Auditd has no rule to collect login and logout events.',
      loglevel => $log_level,
      withpath => false,
    }

    $logentry_data = {
      level     => $log_level,
      msg       => 'Auditd has no rule to collect login and logout events.',
      rulestate => 'not compliant',
    }
  } else {
    $logentry_data = {
      level     => 'ok',
      msg       => 'Auditd has a rule to collect login and logout events.',
      rulestate => 'compliant',
    }
  }

  if($enforce) {

    if($facts['security_baseline_auditd']['logins'] == false) {
      auditd::rule { 'logins policy rule 1':
        content => '-w /var/log/lastlog -p wa -k logins',
      }
      auditd::rule { 'logins policy rule 2':
        content => '-w /var/run/faillock/ -p wa -k logins',
      }
    }
  }

  $logentry = $logentry_default + $logentry_data
  ::security_baseline::logging { 'auditd-logins':
    * => $logentry,
  }
}
