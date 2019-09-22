# check if values of output are contained in expected array

def check_values(val, expected)
  if val.empty? || val.nil?
    false
  else
    output = val.split("\n")
    (output - expected).empty?
  end
end
