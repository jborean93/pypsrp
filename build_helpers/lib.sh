#!/bin/bash


lib::setup::debian_requirements() {
    echo "Installing Debian based pre-requisites"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update

    apt-get -y install \
        gcc \
        gss-ntlmssp \
        libkrb5-dev \
        python3-dev
}

lib::setup::windows_requirements() {
    echo "Installing Windows pre-requisites"

    export PYPSRP_RUN_INTEGRATION=1
    export PYPSRP_SERVER=localhost
    export PYPSRP_USERNAME=psrpuser
    export PYPSRP_PASSWORD=Password123
    export PYPSRP_CERT_DIR="$( echo "${PWD}" | sed -e 's/^\///' -e 's/\//\\/g' -e 's/^./\0:/' )"

    powershell.exe -NoLogo -NoProfile \
        -File ./build_helpers/win-setup.ps1 \
        -UserName "${PYPSRP_USERNAME}" \
        -Password "${PYPSRP_PASSWORD}" \
        -CertPath "${PYPSRP_CERT_DIR}" \
        -InformationAction Continue

    # FIXME: For some reason cert auth is failing with. Need to figure out what's happening here and unset this
    # pypsrp.exceptions.WSManFaultError: Received a WSManFault message. (Code: 2150859262, Machine: localhost,
    # Reason: The WS-Management service cannot process the operation. An attempt to query mapped credential failed.
    # This will happen if the security context associated with WinRM service has changed since the credential was originally mapped
    unset PYPSRP_CERT_DIR
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
    python -m pip install pypsrp[credssp,kerberos]

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
        --verbose \
        --junitxml junit/test-results.xml \
        --cov pypsrp \
        --cov-report xml \
        --cov-report term-missing

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}
