#!/bin/bash -e

if ! command -v nano &> /dev/null
then
    echo "nano is needed for the installion process"
    exit 1
fi

if ! command -v sudo &> /dev/null
then
    echo "sudo is needed for the installion process"
    exit 1
fi

if ! command -v curl &> /dev/null
then
    echo "curl is needed for the installion process"
    exit 1
fi

if ! command -v git &> /dev/null
then
    echo "git is needed for the installion process"
    exit 1
fi

user_name="centralex"
install_dir="/var/lib/centralex"
service_file="/etc/systemd/system/centralex.service"

if [ $# -lt 1 ]; then
    step="root"
else
    step="$1"
fi

echo "running $step setup step"

case "$step" in
    user)
        if [[ $(whoami) != "$user_name" ]]; then
            echo "user step needs to be run as user $user_name"
            exit 1
        fi

        cd "$install_dir"

        echo "installing rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup.sh
        chmod +x rustup.sh
        ./rustup.sh -y --profile minimal
        rm rustup.sh

        echo "cloning source code..."
        git clone https://github.com/soruh/centralex centralex

        echo "creating default config..."
        cp centralex/config-template.json centralex/config.json
    ;;
    root)
        if [[ $(whoami) != "root" ]]; then
            echo "root step needs to be run as root"
            exit 1
        fi

        echo "creating user $user_name..."
        useradd -s /usr/sbin/nologin --create-home --home-dir "$install_dir" "$user_name" 

        echo "creating service file..."
        cat > "$service_file" << EOF
[Unit]
Description=Centralex

[Service]
Enviroment=RUST_BACKTRACE=1
ExecStart=$install_dir/.cargo/bin/cargo run --release
Type=simple
User=centralex
WorkingDirectory=$install_dir/centralex

[Install]
WantedBy=multi-user.target
EOF

    echo "running user step..."
    installer="$(mktemp)"
    cp "$0" "$installer"
    chmod a+rx "$installer"
    sudo -u "$user_name" "$installer" user

    echo "configuring..."
    nano "$install_dir/centralex/config.json"

    echo "enabling service..."
    systemctl enable --now "$(basename "$service_file")"
    ;;
    *)
        echo "unknown installer step $step"
        exit 1
    ;;
esac

echo "success"

exit 0
