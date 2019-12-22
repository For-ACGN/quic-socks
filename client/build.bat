go build -ldflags "-s -w" -o client.exe
set GOOS=linux
set GOARCH=arm
go build -ldflags "-s -w" -o client