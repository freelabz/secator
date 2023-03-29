sudo apt install asciinema
sudo apt update && sudo apt install ttf-mscorefonts-installer
go install -v github.com/cirocosta/asciinema-edit@latest
git clone https://github.com/asciinema/agg
cd agg
cargo build -r
cp target/agg /usr/local/bin/
