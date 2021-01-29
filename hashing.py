# import the hashlib
import hashlib 
import bcrypt


# example hash
word = 'blueberry'
hashed_word = hashlib.md5(word.encode()).hexdigest()

print(word)
print(hashed_word) 

################# salted Hashing ####################

password = b"studyhard"

# Hash a password for the first time, with a certain number of rounds
salt = bcrypt.gensalt(14)
hashed = bcrypt.hashpw(password, salt)
print(salt)
print(hashed)

# Check a plain text string against the salted, hashed digest
print(bcrypt.checkpw(password, hashed))