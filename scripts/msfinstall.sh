#!/bin/sh
# https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb

print_pgp_key() {
  cat <<-EOF
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
2vTa24LE0J2DQg==
=Qa/n
-----END PGP PUBLIC KEY BLOCK-----
EOF
}

install_deb() {
  LIST_FILE=/etc/apt/sources.list.d/metasploit-framework.list
  PREF_FILE=/etc/apt/preferences.d/pin-metasploit.pref
  echo -n "Adding metasploit-framework to your repository list.."
  echo "deb [signed-by=/usr/share/keyrings/metasploit-framework.gpg] $DOWNLOAD_URI/apt lucid main" > $LIST_FILE
  print_pgp_key | gpg --batch --yes --dearmor -o /usr/share/keyrings/metasploit-framework.gpg
  if [ ! -f $PREF_FILE ]; then
    mkdir -p /etc/apt/preferences.d/
    cat > $PREF_FILE <<EOF
Package: metasploit*
Pin: origin downloads.metasploit.com
Pin-Priority: 1000
EOF
  fi
  echo -n "Updating package cache.."
  apt-get update > /dev/null
  echo "OK"
  echo "Checking for and installing update.."
  apt-get install -y --allow-downgrades metasploit-framework
}

install_rpm() {
  echo "Checking for and installing update.."
  REPO_FILE=/etc/yum.repos.d/metasploit-framework.repo
  GPG_KEY_FILE=/etc/pki/rpm-gpg/RPM-GPG-KEY-Metasploit
  echo -n "Adding metasploit-framework to your repository list.."

  cat > /etc/yum.repos.d/metasploit-framework.repo <<EOF
[metasploit]
name=Metasploit
baseurl=$DOWNLOAD_URI/rpm
gpgcheck=1
gpgkey=file://$GPG_KEY_FILE
enabled=1
EOF
  print_pgp_key > ${GPG_KEY_FILE}
  yum install -y metasploit-framework
}

install_suse() {
  echo "Checking for and installing update.."
  GPG_KEY_FILE_DIR=/etc/pki/rpm-gpg
  GPG_KEY_FILE=${GPG_KEY_FILE_DIR}/RPM-GPG-KEY-Metasploit
  echo -n "Adding metasploit-framework to your repository list.."
  if [ ! -d $GPG_KEY_FILE_DIR ]; then
    mkdir -p $GPG_KEY_FILE_DIR
  fi
  zypper ar  -f $DOWNLOAD_URI/rpm metasploit
  print_pgp_key > ${GPG_KEY_FILE}
  rpmkeys --import ${GPG_KEY_FILE}
  zypper install -y metasploit-framework
}

install_apk() {
  apk add -U --no-cache \
    build-base \
    ruby \
    ruby-bigdecimal \
    ruby-bundler \
    ruby-io-console \
    ruby-webrick \
    ruby-dev \
    libffi-dev\
    openssl-dev \
    readline-dev \
    sqlite-dev \
    postgresql-dev \
    libpcap-dev \
    libxml2-dev \
    libxslt-dev \
    yaml-dev \
    zlib-dev \
    ncurses-dev \
    autoconf \
    bison \
    subversion \
    git \
    sqlite \
    nmap \
    libxslt \
    postgresql \
    ncurses
  cd /usr/share && \
	git clone https://github.com/rapid7/metasploit-framework.git
	cd /usr/share/metasploit-framework
	/usr/bin/bundle update --bundler
	/usr/bin/bundle install
  ln -sf /usr/share/metasploit-framework/msfconsole $HOME/.local/bin/msfconsole
}

install_pkg()
{
  (
    cd ~/Downloads

    echo "Downloading package..."
    curl -O "$DOWNLOAD_URI/osx/metasploitframework-latest.pkg"

    echo "Checking signature..."

    if pkgutil --check-signature metasploitframework-latest.pkg; then
      echo "Installing package..."
      installer -pkg metasploitframework-latest.pkg -target /
    fi

    echo "Cleaning up..."
    rm -fv metasploitframework-latest.pkg
  )
}

DOWNLOAD_URI=http://downloads.metasploit.com/data/releases/metasploit-framework
PKGTYPE=unknown
ID=`id -u`

if [ -f /etc/redhat-release ] ; then
  PKGTYPE=rpm
elif [ -f /etc/system-release ] ; then
  # If /etc/system-release is present, this is likely a distro that uses RPM.
  PKGTYPE=rpm
else
  if uname -sv | grep 'Darwin' > /dev/null; then
    PKGTYPE=pkg
  elif [ -f /usr/bin/zypper ] ; then
    PKGTYPE=sus
  elif [ -f /sbin/apk ] ; then
	  PKGTYPE=apk
  else
    PKGTYPE=deb
  fi
fi

if [ "$ID" -ne 0 ]; then
  if ! hash sudo 2>/dev/null; then
    echo "This script must be executed as the 'root' user or with sudo"
    exit 1
  else
    echo "Switching to root user to update the package"
    sudo -E $0 $@
    exit 0
  fi
fi

case $PKGTYPE in
  deb)
    install_deb
    ;;
  sus)
    install_suse
    ;;
  rpm)
    install_rpm
    ;;
  apk)
	  install_apk
	;;
  *)
    install_pkg
esac
