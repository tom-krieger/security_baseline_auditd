# check if values of output are contained in expected array

require 'pp'

def check_values(val, expected, reverse = false)
  if val.empty? || val.nil?
    false
  else
    output = val.split("\n")
    pp output
    pp expected
    if reverse
      ret = (expected - output).empty?
    else
      ret = (output - expected).empty?
    end

    pp ret

    ret
  end
end
