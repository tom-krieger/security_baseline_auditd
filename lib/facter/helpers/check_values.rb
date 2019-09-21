# check if values of output arew contained in expected array

def check_values(output, expected)
  (output - expected).empty?
end
