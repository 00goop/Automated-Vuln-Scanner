import os
import subprocess

API_KEY = 'THIS_IS_A_HARD_CODED_SECRET_please_change'

def get_api_key():
    return API_KEY

def dangerous_eval():
    user = input('enter expression to evaluate: ')
    return eval(user)

def run_command(user_cmd):
    subprocess.call(user_cmd, shell=True)

if __name__ == '__main__':
    print('API key (BAD):', get_api_key())
