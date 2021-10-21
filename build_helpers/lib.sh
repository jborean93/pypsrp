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

    python -m pip install --upgrade pip poetry

    # xmldiff has a dep on lxml which does not have a wheel for Windows Python 3.10. The build deps are complex and
    # they recommend using this unofficial source. This should be removed once lxml adds a cp310 wheel for Windows
    PY_VER="$( python -c "import sys; ver = sys.version_info; print(f'cp{ver.major}{ver.minor}')" )"
    if [ "$(expr substr $(uname -s) 1 5)" == "MINGW" ] && [ "${PY_VER}" == "cp310" ]; then
        PY_ARCH="$( python -c "import sys; print('win_amd64' if sys.maxsize > 2**32 else 'win32')" )"
        WHL_URL="https://download.lfd.uci.edu/pythonlibs/y2rycu7g/lxml-4.6.3-${PY_VER}-${PY_VER}-${PY_ARCH}.whl"

        poetry run python -m pip \
            install \
            "${WHL_URL}"
    fi

    echo "Installing pypsrp"
    poetry install -E kerberos -E credssp

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::sanity::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Sanity Checks"
    fi

    poetry run python -m pycodestyle \
        pypsrp \
        --verbose \
        --show-source \
        --statistics \
        --max-line-length 119

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::tests::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Tests"
    fi

    poetry run python -m pytest \
        --verbose \
        --junitxml junit/test-results.xml \
        --cov pypsrp \
        --cov-report xml \
        --cov-report term-missing

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}
