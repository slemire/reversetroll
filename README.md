# ReverseTroll

A program that listens for clients connections and sends a fake Windows reverse shell to the victims.

This was built as a small project to play with the Go programming language.

There are two versions
- The first one uses the netcat table to look for "active" clients, then calls back back on a specified port. This of course assume that the clients would be using a common port for their reverse shell such as 4444.
- The second version captures traffic from the interface and looks for a reverse shell payload in the application payload. It extract the IP and port from the reverse shell payload then connections to the port
