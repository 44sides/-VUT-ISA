# -VUT-ISA
Network Applications and Administration - File transfer through hidden channel

Client / Server application that allows to transfer a file through a hidden channel where data is transmitted inside ICMP Echo-Request / Response messages. The file must be encrypted before transmission so that it's not transmitted in text form.

### Application run:
secret -r \<file> -s <ip | hostname> [-l]
- -r \<file>: file specification for transfer
- -s <ip | hostname>: ip address / hostname where the file should be sent
- -l: a running program with this parameter turns on the server that listens for incoming ICMP messages and saves the file to the same directory where it was run.

### Task specification:
The program processes the input arguments, reads the file, encrypts it and sends it through ICMP messages to the selected IP address, where the program running in listen (-l) mode captures these messages, decrypts them and saves the file to disk.
- The program can only use ICMP Echo-request / reply messages.
You will need to define a data transfer protocol for proper behavior (eg you need to send the file name, verify that the file has been transferred a whole, etc.).
- Use AES as a cipher.
- The program must deal with a file larger than the maximum packet size on a standard network (1500B), ie it must be able to split a larger file into multiple packets.
