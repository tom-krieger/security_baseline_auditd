# check if values of output are contained in expected array

def check_values(val, expected, reverse = false)
  if val.empty? || val.nil?
    false
  else
    output = val.split("\n")
    if reverse
      (expected - output).empty?
    else
      (output - expected).empty?
    end
  end
end
