# IS2500-rfid-attendance-system
Main implementation of the attendance system RFID reader for the IS2500 course

## Install dependencies
`pip3 install [pi-rc522](https://github.com/ondryaso/pi-rc522)`

## Generate secret HMAC key
The current key found in `hmac.key` is a dummy key for demo purposes.
It should under no circumstances be used in production.
To generate a new key you can use the following OpenSSL command:
`openssl rand -out hmac.key -hex 32`

## Database file
`db.xml` contains an example database file that could be used to store
valid tags in the system
