# @summary 
#    Ensure kernel module loading and unloading is collected (Scored)
#
# Monitor the loading and unloading of kernel modules. The programs insmod (install a kernel module), 
# rmmod (remove a kernel module), and modprobe (a more sophisticated program to load and unload modules, 
# as well as some other features) control loading and unloading of modules. The init_module (load a module) 
# and delete_module (delete a module) system calls control loading and unloading of modules. Any execution 
# of the loading and unloading module programs and system calls will trigger an audit record with an 
# identifier of "modules".
#
# Rationale:
# Monitoring the use of insmod , rmmod and modprobe could provide system administrators with evidence that 
# an unauthorized user loaded or unloaded a kernel module, possibly compromising the security of the system. 
# Monitoring of the init_module and delete_module system calls would reflect an unauthorized user attempting 
# to use a different program to load and unload modules.
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
# @example
#   class { 'security_baseline_auditd::rules::modules':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline_auditd::rules::modules (
  Boolean $enforce,
  String $message   = '',
  String $log_level = 'info',
  Integer $level    = 1,
  Boolean $scored   = true,
) {
  require 'auditd'

  $logentry_default = {
    rulenr    => '4.1.17',
    rule      => 'auditd-modules',
    desc      => 'Ensure kernel module loading and unloading is collected (Scored)',
    level     => $level,
    scored    => $scored,
  }

  if($facts['security_baseline_auditd']['modules'] == false) {
    echo { 'auditd-modules':
      message  => 'Auditd has no rule to collect kernel module loading and unloading events.',
      loglevel => $log_level,
      withpath => false,
    }

    $logentry_data = {
        log_level => $log_level,
        msg       => 'Auditd has no rule to collect kernel module loading and unloading events.',
        rulestate => 'not compliant',
      }
  } else {
    $logentry_data = {
        log_level => 'ok',
        msg       => 'Auditd has a rule to collect kernel module loading and unloading events.',
        rulestate => 'compliant',
      }
  }

  if($enforce) {
    auditd::rule { 'watch modules rule 1':
      content => '-w /sbin/insmod -p x -k modules',
    }
    auditd::rule { 'watch modules rule 2':
      content => '-w /sbin/rmmod -p x -k modules',
    }
    auditd::rule { 'watch modules rule 3':
      content => '-w /sbin/modprobe -p x -k modules',
    }
    if($facts['architecture'] == 'x86_64') {
      auditd::rule { 'watch modules rule 4':
        content => '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules',
      }
    } else {
      auditd::rule { 'watch modules rule 4':
        content => '-a always,exit -F arch=b32 -S init_module -S delete_module -k modules',
      }
    }
  }

  $logentry = $logentry_default + $logentry_data
  ::security_baseline::logging { 'auditd-modules':
    * => $logentry,
  }
}
