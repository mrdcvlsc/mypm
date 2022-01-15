# mypm

A simple password manager written in Java.

**use at your own risk!!!**

this is just a hobby project for the purpose of learning,
the code might have some bugs and vulnerabilities.

----------

### Cryptographic Algorithms Used
- SHA512
- AES128
- CBC

### Inner workings

- when the application is started for the first time, the program will promt the user to enter their new password.
- the application will scan the ```dt.db``` file (an sqlite3 database) inside the ```d``` folder if it's empty or not. This is how the application detects if it the user needs to enter a new password.
- new passwords are hashed using ```SHA512``` and padded with a ```Random Salt``` before it is stored into the ```dt.db``` database.
- the hashed main password (the password that you use to login into the application) is then used as a key to generate the ```RoundKeys``` to be used for the ```AES128``` encryption and decryption in the ```dt.db``` database.
- when adding a record each item is then encrypted with a ```random IV```, this random IV is then appended to the cipher text before it is saved into the ```dt.db```
- everytime the application reads the encrypted cipher text from the database, it split the IV and the cipher text then decrypts it using the AES128 key that was generated using the SHA512 output from the plain text password.
- everytime the passwords is changed the encryptions of all the records of the database is also updated.
- the program will always search for the ```d/dt.db``` database and will not function properly if the database is not existing or corrupted.
