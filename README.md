# DirtyGo
Windows Ransomware - Proof of Concept

This is for educational purposes - author is not responsible for any damage.  

Use with caution.  

Run on Virtual Machine.

# How to build
```go
go mod init dirty_go
go mod tidy
GOOS=windows go build dirty.go
// => dirty.exe
```
[Available as gist](https://gist.github.com/alx3dev/8fc4496a7a1cb0af69dd8e531753d42a)
