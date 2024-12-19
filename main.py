import os
user_input = "ls"
os.system(user_input)  # Kwetsbaar voor command injection

user_input = "print('Hello, world!')"
eval(user_input)  # Onveilige functie
