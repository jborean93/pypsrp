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

    # Getting the version is important so that pip prioritises our local dist
    python -m pip install build
    PSRP_VERSION="$( python -c "import build.util; print(build.util.project_wheel_metadata('.').get('Version'))" )"

    echo "Installing pypsrp"
    python -m pip install pypsrp[credssp,kerberos]=="${PSRP_VERSION}" \
        --find-links dist \
        --verbose

    echo "Installing dev dependencies"
    python -m pip install .[dev]

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
        --verbose \
        --junitxml junit/test-results.xml \
        --cov pypsrp \
        --cov-report xml \
        --cov-report term-missing

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}
