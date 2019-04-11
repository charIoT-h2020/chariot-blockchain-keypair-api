FROM golang:latest
RUN mkdir /app
ADD ./CHARIOTKeypairAPI.go /app/api.go
WORKDIR /app
RUN go build -o main .
EXPOSE 8081
CMD ["/app/main"]
