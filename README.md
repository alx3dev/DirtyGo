# DirtyGo
Windows Ransomware - Proof of Concept

This is for educational purposes - author is not responsible for any damage.  

Use with caution.  

Run on Virtual Machine.

# How it works?
RSA 4096b public key is base64 encoded as string.
On start, we generate 32bits token for AES encryption, that we encrypt with rsa public key and save.
We search for single-character partitions, and encrypt every file with AES.

# How to build
```go
go mod init dirty_go
go mod tidy
GOOS=windows go build dirty.go
// => dirty.exe
```
[Available as gist](https://gist.github.com/alx3dev/8fc4496a7a1cb0af69dd8e531753d42a)
