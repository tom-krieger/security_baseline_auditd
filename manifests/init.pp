# @summary
#    Security baseline and configuration for auditd
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
# @param logfile 
#    Logfile to log into
#
# @param max_log_size
#    Maximal log file size
#
# @param space_left_action
#    What to do when space get low
#
# @param action_mail_acct
#    This option should contain a valid email address or alias. The default address is root. If the email address is not local to 
#    the machine, you must make sure you have email properly configured on your machine and network. Also, this option requires 
#    that /usr/lib/sendmail exists on the machine.
#
# @param admin_space_left_action
#    This parameter tells the system what action to take when the system has detected that it is low on disk space.
#
# @param max_log_file_action 
#    This parameter tells the system what action to take when the system has detected that the max file size limit has been reached. 
#
# @example
#   include ::security_baseline_auditd
class security_baseline_auditd (
  Boolean $enforce                = true,
  String $message                 = '',
  String $log_level               = 'info',
  Integer $level                  = 1,
  Boolean $scored                 = true,
  String $logfile                 = '',
  Integer $max_log_size           = 32,
  String $space_left_action       = 'email',
  String $action_mail_acct        = 'root',
  String $admin_space_left_action = 'halt',
  String $max_log_file_action     = 'keep_logs',
  Array $suid_include             = [],
  Array $suid_exclude             = [],
) {
  class {'security_baseline_auditd::cron::suid_rules':
    include => $suid_include,
    exclude => $suid_exclude,
  }

  $auditd_config = {
    'max_log_file'            => $max_log_size,
    'space_left_action'       => $space_left_action,
    'action_mail_acct'        => $action_mail_acct,
    'admin_space_left_action' => $admin_space_left_action,
    'max_log_file_action'     => $max_log_file_action,
    'buffer_size'             => 8192,
  }
  $maxlog_default = {
    rulenr    => '4.1.1.1',
    rule      => 'auditd-max-log-file',
    desc      => 'Ensure auditd settings are correct (Scored)',
    level     => $level,
    scored    => $scored,
  }
  $disable_default = {
    rulenr    => '4.1.1.2',
    rule      => 'auditd-disable-when-full',
    desc      => 'Ensure system is disabled when audit logs are full (Scored)',
    level     => $level,
    scored    => $scored,
  }
  $maxlogaction_default = {
    rulenr    => '4.1.1.3',
    rule      => 'auditd-disable-when-full',
    desc      => 'Ensure system is disabled when audit logs are full (Scored)',
    level     => $level,
    scored    => $scored,
  }
  $service_default = {
    rulenr    => '4.1.2',
    rule      => 'auditd-service',
    desc      => 'Ensure auditd service is enabled (Scored)',
    level     => $level,
    scored    => $scored,
  }

  if($facts['security_baseline_auditd']['max_log_file'] == 'none') {
    $maxlog_entry = {
      log_level => $log_level,
      msg       => 'Auditd setting for max_log_file is not correct.',
      rulestate => 'not compliant',
    }
  } else {
    $maxlog_entry = {
      log_level => 'ok',
      msg       => 'Auditd setting for max_log_file is correct.',
      rulestate => 'compliant',
    }
  }
  if(
    ($facts['security_baseline_auditd']['action_mail_acct'] == 'none') or
    ($facts['security_baseline_auditd']['admin_space_left_action'] == 'none') or
    ($facts['security_baseline_auditd']['space_left_action'] == 'none')
  ) {
    $disable_entry = {
      log_level => $log_level,
      msg       => 'Auditd setting for action_mail_acct and/or admin_space_left_action and/or space_left_action are not correct.',
      rulestate => 'not compliant',
    }
  } else {
    $disable_entry = {
      log_level => 'ok',
      msg       => 'Auditd setting for action_mail_acct, admin_space_left_action and space_left_action are correct.',
      rulestate => 'compliant',
    }
  }
  if($facts['security_baseline_auditd']['max_log_file_action'] == 'none') {
    $maxlogaction_entry = {
      log_level => $log_level,
      msg       => 'Auditd setting for max_log_file_action is not correct.',
      rulestate => 'not compliant',
    }
  } else {
    $maxlogaction_entry = {
      log_level => 'ok',
      msg       => 'Auditd setting for max_log_file_action is correct.',
      rulestate => 'ompliant',
    }
  }

  if($facts['security_baseline_auditd']['srv_auditd'] == 'none') {
    echo { 'auditd-service':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }

    $service_entry = {
      log_level => $log_level,
      msg       => 'Auditd service is not running.',
      rulestate => 'not compliant',
    }
  } else {
    $service_entry = {
      log_level => 'ok',
      msg       => 'Auditd service is running.',
      rulestate => 'compliant',
    }
  }

  if($enforce) {
    class { '::auditd':
      * => $auditd_config,
    }
  }

  $maxlog = $maxlog_default + $maxlog_entry
  ::security_baseline::logging { 'auditd-max-log-file':
    * => $maxlog,
  }

  $disable = $disable_default + $disable_entry
  ::security_baseline::logging { 'auditd-disable-when-full':
    * => $disable,
  }

  $maxlogaction = $maxlogaction_default + $maxlogaction_entry
  ::security_baseline::logging { 'auditd-max-log-file-action':
    * => $maxlogaction,
  }

  $service = $service_default + $service_entry
  ::security_baseline::logging { 'auditd-service':
    * => $service,
  }

  class { '::security_baseline_auditd::rules':
    enforce   => $enforce,
    message   => $message,
    log_level => $log_level,
    level     => $level,
    scored    => $scored,
    require   => Class['::auditd'],
  }
}
