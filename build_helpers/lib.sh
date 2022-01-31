#!/bin/bash


lib::setup::debian_requirements() {
    echo "Installing Debian based pre-requisites"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update

    apt-get -y install \
        gcc \
        gss-ntlmssp \
        libkrb5-dev \
        openssh-server \
        python3-dev

    if [ ! -d "/root/.ssh" ]; then
        mkdir /root/.ssh
    fi
    chmod 700 /root/.ssh

    ssh-keygen -o -a 100 -t ed25519 -f /root/.ssh/id_ed25519 -q -N ""
    cp /root/.ssh/id_ed25519.pub /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/*

    echo "Subsystem powershell /usr/bin/pwsh -sshs -NoLogo" >> /etc/ssh/sshd_config
    systemctl restart sshd.service

    echo "Testing out SSH authentication"
    ssh -o IdentityFile=/root/.ssh/id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null localhost whoami

    export PYPSRP_SSH_SERVER=localhost
    export PYPSRP_SSH_KEY_PATH=/root/.ssh/id_ed25519
}

lib::setup::windows_requirements() {
    echo "Installing Windows pre-requisites"

    export PYPSRP_RUN_INTEGRATION=1
    export PYPSRP_SERVER=localhost
    export PYPSRP_SSH_SERVER=localhost
    export PYPSRP_SSH_KEY_PATH="$( echo ~/.ssh/id_ed25519 | sed -e 's/^\///' -e 's/\//\\/g' -e 's/^./\0:/' )"
    export PYPSRP_SSH_IS_WINDOWS=true
    export PYPSRP_USERNAME=psrpuser
    export PYPSRP_PASSWORD=Password123
    export PYPSRP_CERT_PATH="$( echo "${PWD}/cert.pem" | sed -e 's/^\///' -e 's/\//\\/g' -e 's/^./\0:/' )"

    powershell.exe -NoLogo -NoProfile \
        -File ./build_helpers/win-setup.ps1 \
        -UserName "${PYPSRP_USERNAME}" \
        -Password "${PYPSRP_PASSWORD}" \
        -CertPath "${PYPSRP_CERT_PATH}" \
        -InformationAction Continue

    # FIXME: For some reason cert auth is failing and the connection is dropped.
    # Tried disabling TLS 1.3 and HTTP2 but that doesn't work. Needs further
    # investigation.
    unset PYPSRP_CERT_PATH
}

lib::setup::system_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Installing System Requirements"
    fi

    if [ -f /etc/debian_version ]; then
        lib::setup::debian_requirements

    elif [ "$(expr substr $(uname -s) 1 5)" == "MINGW" ]; then
        lib::setup::windows_requirements

    else
        echo "Distro not found!"
        false
    fi

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::setup::python_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Installing Python Requirements"
    fi

    python -m pip install --upgrade pip setuptools wheel

    echo "Installing pypsrp"
    if [ "$(expr substr $(uname -s) 1 5)" == "MINGW" ]; then
        DIST_LINK_PATH="$( echo "${PWD}/dist" | sed -e 's/^\///' -e 's/\//\\/g' -e 's/^./\0:/' )"
    else
        DIST_LINK_PATH="${PWD}/dist"
    fi

    python -m pip install pypsrp \
        --no-index \
        --find-links "file://${DIST_LINK_PATH}" \
        --no-build-isolation \
        --no-dependencies \
        --verbose
    python -m pip install pypsrp[credssp,kerberos,named_pipe,socks,ssh]

    echo "Installing dev dependencies"
    python -m pip install -r requirements-dev.txt

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::sanity::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Sanity Checks"
    fi

    python -m black . --check
    python -m isort . --check-only
    python -m mypy .

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::tests::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Tests"
    fi

    # Weirdly WinRM errors with the following randomly on the first connection.
    # This will flush out this error so the tests run without complications.
    # Illegal operation attempted on a registry key that has been marked for deletion.
    if [ -n "${PYPSRP_SERVER+set}" ]; then
        PYTHONPATH=src python ./build_helpers/check-winrm.py
    fi

    python -m pytest \
        tests/tests_pypsrp \
        --verbose

    python -m pytest \
        tests/tests_psrp \
        --verbose \
        --junitxml junit/test-results.xml \
        --cov psrp \
        --cov-report xml \
        --cov-report term-missing

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}
