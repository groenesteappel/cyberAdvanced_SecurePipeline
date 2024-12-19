print("Hello, World!")

# Kwetsbare code om SAST te triggeren
user_input = "os.system('ls')"
eval(user_input)
