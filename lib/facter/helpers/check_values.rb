# check if values of output are contained in expected array

require 'pp'

def check_values(val, expected, reverse = false, debug = false)
  if val.empty? || val.nil?
    false
  else
    output = val.split("\n")
    if debug
      pp output
      pp expected
    end

    if reverse
      if debug
        pp (expected - output)
      end
      ret = (expected - output).empty?
    else
      if debug
        pp (output - expected)
      end
      ret = (output - expected).empty?
    end

    if debug
      pp ret
    end

    ret
  end
end
