go build -o api
patchelf --set-rpath ./ ./api
./api
