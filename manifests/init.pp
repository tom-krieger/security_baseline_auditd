# @summary
#    Security baseline and configuratio for auditd
#
# System auditing, through auditd, allows system administrators to monitor their systems such that 
# they can detect unauthorized access or modification of data. By default, auditd will audit 
# SELinux AVC denials, system logins, account modifications, and authentication events. Events will 
# be logged to /var/log/audit/audit.log. The recording of these events will use a modest amount of 
# disk space on a system. If significantly more events are captured, additional on system or off 
# system storage may need to be allocated.
#
# The recommendations in this section implement an audit policy that produces large quantities of 
# logged data. In some environments it can be challenging to store or process these logs and as such 
# they are marked as Level 2 for both Servers and Workstations. Note: For 64 bit systems that have 
# arch as a rule parameter, you will need two rules: one for 64 bit and one for 32 bit systems. 
# For 32 bit systems, only one rule is needed.
#
# @example
#   include security_baseline_auditd::ecurity_baseline_auditd
class security_baseline_auditd (
  Boolean $enforce                = true,
  String $message                 = '',
  String $log_level               = 'info',
  String $logfile                 = '',
  Integer $max_log_size           = 32,
  String $space_left_action       = 'email',
  String $action_mail_acct        = 'root',
  String $admin_space_left_action = 'halt',
  String $max_log_file_action     = 'keep_logs',
) {
  if($enforce) {
    $auditd_config = {
      'max_log_file'            => $max_log_size,
      'space_left_action'       => $space_left_action,
      'action_mail_acct'        => $action_mail_acct,
      'admin_space_left_action' => $admin_space_left_action,
      'max_log_file_action'     => $max_log_file_action,
      'buffer_size'             => 8192,
    }

    class { '::auditd':
      * => $auditd_config,
    }
  } else {
    if(
      ($facts['security_baseline_auditd']['max_log_file'] == 'none') or
      ($facts['security_baseline_auditd']['action_mail_acct'] == 'none') or
      ($facts['security_baseline_auditd']['admin_space_left_action'] == 'none') or
      ($facts['security_baseline_auditd']['max_log_file_action'] == 'none')
    ) {
      echo { 'auditd-settings':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

      ::security_baseline::logging { 'auditd-settings':
        rulenr    => 'auditd',
        rule      => 'auditd',
        desc      => 'Ensure auditd settings are correct (Scored)',
        level     => $log_level,
        msg       => 'Auditd settings are not correct.',
        rulestate => 'not compliant',
      }
    }

    if($facts['security_baseline_auditd']['srv_auditd'] == 'none') {
      echo { 'auditd-service':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

      ::security_baseline::logging { 'auditd-service':
        rulenr    => 'auditd',
        rule      => 'auditd',
        desc      => 'Ensure auditd servie is running (Scored)',
        level     => $log_level,
        msg       => 'Auditd service is not running.',
        rulestate => 'not compliant',
      }
    }
  }

  class { '::security_baseline_auditd::rules':
    enforce   => $enforce,
    message   => $message,
    log_level => $log_level,
    require   => Class['::auditd'],
    before    => Exec['reload-auditd']
  }

  exec {'reload-auditd':
    command => '/sbin/augenrules --load',
  }
}
