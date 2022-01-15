# mypm

A simple password manager written in Java.

this is just a hobby project for the purpose of learning,
the code might have some bugs and vulnerabilities.

**USE AT YOUR OWN RISK!!!**

----------

### Cryptographic Algorithms Used
- SHA512 Hash Function
- AES-128 Block Cipher
- CBC Mode of Encryption

### Inner workings

- when the application is started for the first time, the program will promt the user to enter their new password.
- the application will read the ```dt.db``` file (an sqlite3 database) inside the ```d``` folder if it's empty or not. This is how the application detects if it the user needs to enter a new password.
- for new user they will be prompted to input a new starting password, the new password is then concatenated with a ```random salt```, then it will be hashed using ```SHA512``` and then will be concatenated again with the generated random salt from before, then stored into the ```dt.db``` database.
- when loging in to the application, the application will get the random salt from the database and the hashed password, the random salt will then be concatenated to the input password then hashed to get an Auth hash, this Auth hash will be compared to the hashed password in the database, this is how the application works in the login promt.
- the resulting hash of your password (the password that you use to login into the application) and the ```random salt``` is then used to generate the key for the ```AES128``` encryption and decryption when reading from and writing into the ```dt.db``` database.
- when adding a record each item is then encrypted using AES128 with a ```random IV```, this random IV is then appended to the cipher text before it is saved into the ```dt.db```
- everytime the application reads the encrypted cipher text from the database, it split the IV and the cipher text then decrypts it using the AES128 key.
- everytime the passwords is changed the encryptions of all the records of the database is also updated.
- the program will always search for the ```d/dt.db``` database and will not function properly if the database is not existing or corrupted.

### Characteristics
- On two separate computers, if the two users have the same exact password, their resulting hash would still be different from each other because of the random salt.
- a similar or exact text input to the database would produce different cipher text because of the random IV's.

### Note
- the ```d/dt.db``` is where all the encrypted data is stored, the encryption and decryption only runs in the application.
- if the ```d/dt.db``` is deleted all data won't be recovered.
- to make a new account you need to replace the ```d/dt.db``` file with an empty ```dt.db```.
- the ```dt.db``` should always be named as it is and be placed on the ```d``` folder,  because that is the file that the application will scan and not other filenames.
