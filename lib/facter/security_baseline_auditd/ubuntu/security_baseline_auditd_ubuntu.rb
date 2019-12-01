# frozen_string_literal: true

require 'facter/security_baseline_auditd/common/check_values'
require 'pp'

# security_baseline_auditd_ubuntu.rb
# Gather facts around auditd

def security_baseline_auditd_ubuntu(_os, _distid, _release)
    security_baseline_auditd = {}
    arch = Facter.value(:architecture)

    security_baseline_auditd
end
