#!/usr/bin/env python3

import datetime, sys, os, base64, json, concurrent.futures, subprocess, jwt

start = datetime.datetime.now()

# ----------------------------------------

def unique(sequence):
	seen = set()
	return [x for x in sequence if not (x in seen or seen.add(x))]

def read_file(file):
	tmp = []
	with open(file, "r", encoding = "ISO-8859-1") as wordlist:
		for word in wordlist:
			word = word.strip() # strip all spacing
			# word = word.strip("\n") # strip only new lines
			if word:
				tmp.append(word)
	wordlist.close()
	return unique(tmp)

# ----------------------------------------

class JWTBF:

	def __init__(
		self,
		wordlist,
		token,
		threads
	):
		self.__length   = len(wordlist)
		self.__wordlist = self.__split(wordlist, threads)
		self.__alg      = None
		self.__options  = None
		self.__token    = token
		self.__threads  = threads
		self.__cracked  = False

	def __split(self, wordlist, threads):
		if threads > 1:
			k, m = divmod(len(wordlist), threads)
			return list(filter(None, [wordlist[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)] for i in range(threads)]))
		else:
			return [wordlist]

	def __print_error(self, msg):
		print(("ERROR: {0}").format(msg))

	def __crack(self, index):
		for secret in self.__wordlist[index]:
			if self.__cracked:
				break
			try:
				jwt.decode(self.__token, secret, algorithms = [self.__alg], options = self.__options)
				self.__cracked = True
				print(("JWT signature was cracked successfully! Secret: {0}").format(secret))
			except (ValueError, jwt.exceptions.InvalidSignatureError):
				continue

	def run(self):
		array = self.__token.split(".")
		if len(array) != 3:
			self.__print_error("Invalid JWT format")
		else:
			header = None
			try:
				header = json.loads(base64.b64decode(array[0]).decode("ISO-8859-1"))
			except ValueError:
				self.__print_error("Invalid JWT format")
			if header:
				if "alg" not in header:
					self.__print_error("No algorithm found")
				else:
					self.__alg = header["alg"]
					self.__options = {}
					if "kid" in header:
						self.__options["kid"] = header["kid"]
					print(("Secrets: {0} | Chunk size: {1} | Max. Threads: {2}").format(self.__length, len(self.__wordlist[0]), self.__threads))
					with concurrent.futures.ThreadPoolExecutor(max_workers = self.__threads) as executor:
						subprocesses = []
						for index in range(0, len(self.__wordlist)):
							subprocesses.append(executor.submit(self.__crack, index))
						concurrent.futures.wait(subprocesses)
					if not self.__cracked:
						self.__print_error("Cannot crack JWT")

# ----------------------------------------

# my own validation algorithm

class Validate:

	def __init__(self):
		self.__proceed = True
		self.__args    = {
			"wordlist": None,
			"token"   : None,
			"threads" : None
		}

	def __basic(self):
		self.__proceed = False
		print("JWT BF v2.2 ( github.com/ivan-sincek/jwt-bf )")
		print("")
		print("Usage:   python3 jwt_bf.py -w wordlist    -t token       [-th threads]")
		print("Example: python3 jwt_bf.py -w secrets.txt -t xxx.yyy.zzz [-th 50     ]")

	def __advanced(self):
		self.__basic()
		print("")
		print("DESCRIPTION")
		print("    Brute force a JWT token")
		print("WORDLIST")
		print("    Wordlist to use")
		print("    Spacing will be stripped, empty lines ignored, and duplicates removed")
		print("    -w <wordlist> - secrets.txt | etc.")
		print("TOKEN")
		print("    JWT token to crack")
		print("    -t <token> - xxx.yyy.zzz | etc.")
		print("THREADS")
		print("    Number of parallel threads to run")
		print("    Wordlist will be split equally between threads")
		print("    Default: 10")
		print("    -th <threads> - 50 | etc.")

	def __print_error(self, msg):
		print(("ERROR: {0}").format(msg))

	def __error(self, msg, help = False):
		self.__proceed = False
		self.__print_error(msg)
		if help:
			print("Use -h for basic and --help for advanced info")

	def __validate(self, key, value):
		value = value.strip()
		if len(value) > 0:
			# --------------------------------
			if key == "-w" and self.__args["wordlist"] is None:
				self.__args["wordlist"] = value
				if not os.path.isfile(self.__args["wordlist"]):
					self.__error("Wordlist does not exists")
				elif not os.access(self.__args["wordlist"], os.R_OK):
					self.__error("Wordlist does not have read permission")
				elif not os.stat(self.__args["wordlist"]).st_size > 0:
					self.__error("Wordlist is empty")
				else:
					self.__args["wordlist"] = read_file(self.__args["wordlist"])
					if not self.__args["wordlist"]:
						self.__error("No secrets were found")
			# --------------------------------
			elif key == "-t" and self.__args["token"] is None:
				self.__args["token"] = value
			# --------------------------------
			elif key == "-th" and self.__args["threads"] is None:
				self.__args["threads"] = value
				if not self.__args["threads"].isdigit():
					self.__error("Number of parallel threads to run must be numeric")
				else:
					self.__args["threads"] = int(self.__args["threads"])
					if self.__args["threads"] < 1:
						self.__error("Number of parallel threads to run must be greater than zero")
			# --------------------------------

	def __check(self, argc):
		count = 0
		for key in self.__args:
			if self.__args[key] is not None:
				count += 1
		return argc - count == argc / 2

	def run(self):
		# --------------------------------
		argc = len(sys.argv) - 1
		# --------------------------------
		if argc == 0:
			self.__advanced()
		# --------------------------------
		elif argc == 1:
			if sys.argv[1] == "-h":
				self.__basic()
			elif sys.argv[1] == "--help":
				self.__advanced()
			else:
				self.__error("Incorrect usage", True)
		# --------------------------------
		elif argc % 2 == 0 and argc <= len(self.__args) * 2:
			for i in range(1, argc, 2):
				self.__validate(sys.argv[i], sys.argv[i + 1])
			if self.__args["wordlist"] is None or self.__args["token"] is None or not self.__check(argc):
				self.__error("Missing a mandatory option (-w, -t) and/or optional (-th)", True)
		# --------------------------------
		else:
			self.__error("Incorrect usage", True)
		# --------------------------------
		if self.__proceed:
			if not self.__args["threads"]:
				self.__args["threads"] = 10
		# --------------------------------
		return self.__proceed
		# --------------------------------

	def get_arg(self, key):
		return self.__args[key]

# ----------------------------------------

def main():
	validate = Validate()
	if validate.run():
		print("#######################################################################")
		print("#                                                                     #")
		print("#                             JWT BF v2.2                             #")
		print("#                               by Ivan Sincek                        #")
		print("#                                                                     #")
		print("# Brute force a JWT token.                                            #")
		print("# GitHub repository at github.com/ivan-sincek/jwt-bf.                 #")
		print("#                                                                     #")
		print("#######################################################################")
		jwt_bf = JWTBF(
			validate.get_arg("wordlist"),
			validate.get_arg("token"),
			validate.get_arg("threads")
		)
		jwt_bf.run()
		print(("Script has finished in {0}").format(datetime.datetime.now() - start))

if __name__ == "__main__":
	main()
