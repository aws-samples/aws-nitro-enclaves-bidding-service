sudo nitro-cli terminate-enclave --all

docker build -t vsock-poc .
sudo nitro-cli build-enclave --docker-uri vsock-poc --output-file ~/vsock_poc.eif

sudo nitro-cli run-enclave --eif-path ~/vsock_poc.eif --cpu-count 2 --memory 4096 --debug-mode