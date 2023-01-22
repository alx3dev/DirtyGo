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
