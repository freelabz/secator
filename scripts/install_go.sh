sudo rm -rf /usr/local/go
wget https://golang.org/dl/go1.22.0.linux-amd64.tar.gz
tar -xvf go1.22.0.linux-amd64.tar.gz
rm go1.22.0.linux-amd64.tar.gz || true
sudo mv go /usr/local
sudo rm /usr/bin/go
sudo ln -s /usr/local/go/bin/go /usr/bin/go