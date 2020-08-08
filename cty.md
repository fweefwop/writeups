# Problem:
namp scan get the following:
'''  
2500/tcp open     rtsserv?
| fingerprint-strings: 
|   GenericLines, GetRequest, HTTPOptions, NULL: 
|_    Warning: this server only sends one line at a time. If you've opened a shell, this may lead to some weird shenanigans until you are able to get a proper shell with netcat.Welcome to the C-Ty! You notice a canary watching over these parts. But can you get past it with the right set of words? Input encoded in hex:
'''  
