#!venv/bin/python
import sys
import argparse
from stegpi import run

sys.dont_write_bytecode = True

parser = argparse.ArgumentParser()

parser.add_argument('action', nargs='?', choices=['embed', 'extract'])
parser.add_argument('-mt', '--method')
parser.add_argument('-if', '--image_file')
parser.add_argument('-mf', '--message_file')
parser.add_argument('-m', '--message')
parser.add_argument('-p', '--password')
parser.add_argument('-o', '--output')

args = parser.parse_args()

action = args.action
method = args.method
image_file = args.image_file
message_file = args.message_file
message = args.message
password = args.password
output = args.output

run(action, message, message_file, password, image_file, output)
