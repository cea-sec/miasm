#!/bin/sh
set -e
set -u

error_exit() {
    echo "ERROR: $1" >&2
    exit "${2:-1}"
}

warn() {
    echo "WARNING: $1" >&2
}

success() {
    echo "$1"
}

if [ ! -f "requirements.txt" ]; then
    error_exit "requirements.txt not found. Are you in the correct directory?" 2
fi

if [ ! -f "setup.py" ]; then
    error_exit "setup.py not found. Are you in the correct directory?" 2
fi

if ! sudo -n true 2>/dev/null; then
    warn "May need to enter password for sudo operations"
fi

echo "Installing miasm Python dependencies..."
if ! pip3 install -r requirements.txt --user; then
    error_exit "Failed to install Python dependencies from requirements.txt" 3
fi
success "Python dependencies installed successfully"

echo "Installing optional dependencies..."
if [ -f "optional_requirements.txt" ]; then
    if ! pip3 install -r optional_requirements.txt --user; then
        warn "Failed to install optional dependencies. Continuing anyway..."
    else
        success "Optional dependencies installed successfully"
    fi
else
    warn "optional_requirements.txt not found. Skipping optional dependencies."
fi

echo "Updating package lists..."
if ! sudo apt update; then
    error_exit "Failed to update package lists" 4
fi
success "Package lists updated"

echo "Installing clang and z3..."
if ! sudo apt install -y clang z3; then
    error_exit "Failed to install clang and z3" 5
fi
success "clang and z3 installed successfully"

if ! command -v clang >/dev/null 2>&1; then
    error_exit "clang installation verification failed" 6
fi

if ! command -v z3 >/dev/null 2>&1; then
    error_exit "z3 installation verification failed" 6
fi

echo "Building miasm..."
if ! python setup.py build; then
    error_exit "Failed to build miasm" 7
fi
success "miasm built successfully"

echo "Installing miasm..."
if ! python setup.py install; then
    error_exit "Failed to install miasm. Check if you need --user flag or proper permissions" 8
fi
success "miasm installed successfully"

success "All operations completed successfully!"