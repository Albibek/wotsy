# Wotsy
The privacy-oriented one-time-secret service in Rust and Webassembly

# State
This was written during one of the hackathons just to try WebAssembly. There is no clear view of this project's future.
It will heavily depends on community and user demand for such funcionality. At this time the code is written quick
and dirty, including unwraps and unneeded allocations.

# In a nutshell
The main feature is that on the server side there is no knowlege of encryption keys, so secrets baing shared don't leak
to server. Most of the work is done on client:

* AES-256 key and IV are generated
* The key is placed into the link after fragment(\#) delimiter, so it never reaches server side
* The cleartext is encrypted using the key and sent to the server along with the IV where it is stored during a limited time
* When read form the server, the data is shown to user and decrypted client-side, while being deleted on server
