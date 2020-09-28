all: pam_awsstssession_go.so

clean:
	rm -f pam_awsstssession_go.so pam_awsstssession_go.h

pam_awsstssession_go.so: pam_awsstssession_go.go utils.go
	go build -o "$@" -buildmode=c-shared $^

aws-iam-emulator: ${GOPATH}/bin/aws-iam-emulator

${GOPATH}/bin/aws-iam-emulator:
	go get github.com/moriyoshi/aws-iam-emulator

test:
	docker run --rm -v "${PWD}:/go/src/stage:rw" -it "golang:1.15-buster" sh -c 'cd /go/src/stage && ls -l && make aws-iam-emulator pam_awsstssession_go.so && ./test.sh'

.PHONY: all clean aws-iam-emulator test
