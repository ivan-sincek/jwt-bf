#!/usr/bin/env python3

import datetime
import sys
import os
import base64
import json
import math
import concurrent.futures
import subprocess
import jwt

start = datetime.datetime.now()

# -------------------------- INFO --------------------------

def basic():
	global proceed
	proceed = False
	print("JWT BF v1.3 ( github.com/ivan-sincek/jwt-bf )")
	print("")
	print("Usage:   python3 jwt_bf.py -w wordlist    -t token             -m maximum")
	print("Example: python3 jwt_bf.py -w secrets.txt -t xxxxx.yyyyy.zzzzz -m 50")

def advanced():
	basic()
	print("")
	print("DESCRIPTION")
	print("    Brute force a JWT token")
	print("WORDLIST")
	print("    Wordlist to use")
	print("    Spacing will be stripped, empty lines ignored, and duplicates removed")
	print("    -w <wordlist> - secrets.txt | etc.")
	print("TOKEN")
	print("    JWT token to crack")
	print("    -t <token> - xxxxx.yyyyy.zzzzz | etc.")
	print("MAXIMUM")
	print("    Maximum number of threads")
	print("    Wordlist will be split equally between threads")
	print("    Default: 10")
	print("    -m <maximum> - 50 | etc.")

# ------------------- MISCELENIOUS BEGIN -------------------

def unique(sequence):
	seen = set()
	return [x for x in sequence if not (x in seen or seen.add(x))]

def read_file(file):
	tmp = []
	with open(file, "r", encoding = "ISO-8859-1") as wordlist:
		for word in wordlist:
			# strip all spacing
			word = word.strip()
			# strip only new lines
			# word = word.strip("\n")
			if word:
				tmp.append(word)
	wordlist.close()
	return unique(tmp)

# -------------------- MISCELENIOUS END --------------------

# -------------------- VALIDATION BEGIN --------------------

# my own validation algorithm

proceed = True

def print_error(msg):
	print(("ERROR: {0}").format(msg))

def error(msg, help = False):
	global proceed
	proceed = False
	print_error(msg)
	if help:
		print("Use -h for basic and --help for advanced info")

args = {"wordlist": None, "token": None, "maximum": None}

def validate(key, value):
	global args
	value = value.strip()
	if len(value) > 0:
		if key == "-w" and args["wordlist"] is None:
			args["wordlist"] = value
			if not os.path.isfile(args["wordlist"]):
				error("Wordlist does not exists")
			elif not os.access(args["wordlist"], os.R_OK):
				error("Wordlist does not have read permission")
			elif not os.stat(args["wordlist"]).st_size > 0:
				error("Wordlist is empty")
			else:
				args["wordlist"] = read_file(args["wordlist"])
				if not args["wordlist"]:
					error("No secrets were found")
		elif key == "-t" and args["token"] is None:
			args["token"] = value
		elif key == "-m" and args["maximum"] is None:
			args["maximum"] = value
			if not args["maximum"].isdigit():
				error("Maximum number of threads must be numeric")
			else:
				args["maximum"] = int(args["maximum"])
				if args["maximum"] < 1:
					error("Maximum number of threads must be greater than zero")

def check(argc, args):
	count = 0
	for key in args:
		if args[key] is not None:
			count += 1
	return argc - count == argc / 2

argc = len(sys.argv) - 1

if argc == 0:
	advanced()
elif argc == 1:
	if sys.argv[1] == "-h":
		basic()
	elif sys.argv[1] == "--help":
		advanced()
	else:
		error("Incorrect usage", True)
elif argc % 2 == 0 and argc <= len(args) * 2:
	for i in range(1, argc, 2):
		validate(sys.argv[i], sys.argv[i + 1])
	if args["wordlist"] is None or args["token"] is None or not check(argc, args):
		error("Missing a mandatory option (-w, -t) and/or optional (-m)", True)
else:
	error("Incorrect usage", True)

# --------------------- VALIDATION END ---------------------

# ----------------------- TASK BEGIN -----------------------

cracked = False

def jwt_crack(wordlist, token, alg, options):
	global cracked
	for secret in wordlist:
		if cracked:
			break
		try:
			jwt.decode(token, secret, algorithms = [alg], options = options)
			cracked = True
			print(("JWT signature was cracked successfully! Secret: {0}").format(secret))
		except (ValueError, jwt.exceptions.InvalidSignatureError):
			continue

def jwt_bf(wordlist, token, maximum = 10):
	global cracked
	header = None
	pos = token.find(".")
	if pos < 0:
		print_error("Invalid JSON format")
	else:
		try:
			header = json.loads(base64.b64decode(token[0:pos]).decode("ISO-8859-1"))
		except ValueError:
			print_error("Invalid JSON format")
	if header is not None:
		alg = header.get("alg")
		if alg is None:
			print_error("No algorithm found")
		else:
			options = {}
			kid = header.get("kid")
			if kid is not None:
				options = {"kid": kid}
			length = len(wordlist)
			size = math.ceil(length / maximum)
			wordlist = [wordlist[i:i+size] for i in range(0, length, size)]
			print(("Secrets: {0} | Chunk Size: {1} | Max. Threads: {2}").format(length, size, maximum))
			with concurrent.futures.ThreadPoolExecutor(max_workers = maximum) as executor:
				for chunk in wordlist:
					executor.submit(jwt_crack, chunk, token, alg, options)
			if not cracked:
				print("Cannot crack JWT")

if proceed:
	print("#######################################################################")
	print("#                                                                     #")
	print("#                             JWT BF v1.3                             #")
	print("#                               by Ivan Sincek                        #")
	print("#                                                                     #")
	print("# Brute force a JWT token.                                            #")
	print("# GitHub repository at github.com/ivan-sincek/jwt-bf.                 #")
	print("# Feel free to donate bitcoin at 1BrZM6T7G9RN8vbabnfXu4M6Lpgztq6Y14.  #")
	print("#                                                                     #")
	print("#######################################################################")
	if args["maximum"] is None:
		args["maximum"] = 10
	jwt_bf(args["wordlist"], args["token"], args["maximum"])
	end = datetime.datetime.now()
	print(("Script has finished in ${0}").format(end - start))

# ------------------------ TASK END ------------------------
