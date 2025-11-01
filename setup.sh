docker run -it ubuntu bash
cd ~
apt update
apt install -y git
apt install -y curl
apt install -y build-essential
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"  
git clone https://github.com/hamesjan/syscept
cd syscept
cargo run 