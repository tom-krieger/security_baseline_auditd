# @summary 
#    Install a daily cronjob to get all suid binaries
#
# Create a cronjob to collect all suid binariers and create auditd rules for them. The cronjob
# will exclude certain filesystems automatically, e. g. filesystems with nosuid option.
#
# @param include
#    Filesystems to include, can not be set together with exclude
#
# @param exclude
#    Filesystems to exclude can not be set together with include 
#
# @example
#   include security_baseline_auditd::cron::suid_rules
class security_baseline_auditd::cron::suid_rules (
  Array $include = [],
  Array $exclude = [],
) {
  if(!empty($include) and !empty($exclude)) {
    fail('Please include directories or exclude them but you can not do both!')
  }

  concat { '/etc/cron.daily/suid-audit':
    ensure => present,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  concat::fragment {'suid_cron_top':
    target => '/etc/cron.daily/suid-audit',
    source => 'puppet:///modules/security_baseline_auditd/suid_auditd_top',
    order  => 01,
  }

  if(empty($include)) {
    $tmp_include = ''

    if(empty($exclude)) {
      $tmp_exclude = ''
    } else {
      $tmp_exclude = "-e ${exclude.join('-e ')}"
    }

    concat::fragment {'suid_cron_body':
      target  => '/etc/cron.daily/suid-audit',
      content => epp('security_baseline_auditd/suid_auditd_exclude.epp', { 'exclude' => $tmp_exclude}),
      order   => 10,
    }

  } else {
    $tmp_include = "-e ${include.join(' ')}"
      concat::fragment {'suid_cron_body':
      target  => '/etc/cron.daily/suid-audit',
      content => epp('security_baseline_auditd/suid_auditd_include.epp', { 'include' => $tmp_include}),
      order   => 10,
    }
  }

  concat::fragment {'suid_cron_end':
    target => '/etc/cron.daily/suid-audit',
    source => 'puppet:///modules/security_baseline_auditd/suid_auditd_end',
    order  => 99,
  }
}
