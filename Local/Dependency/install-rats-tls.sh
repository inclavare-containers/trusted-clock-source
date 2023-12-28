#!/bin/bash

set -e

function FATAL() {
    local msg="$1"

    printf "\x0f"
    printf "\x1b)B"
    printf "\x1b[?25h"
    printf "\x1b[0m" ## Reset
    printf "\x1b[1;91m" ## Light Red
    printf "[x] ERROR: "
    printf "\x1b[0m" ## Reset
    printf -- "$msg"
    printf "\n"

    exit 1
}

function copy_specified_files() {
    local src_dir="$(readlink -f "$1")"
    local dst_dir="$(readlink -f "$2")"
    local find_dir="$3"
    local file_ext="$4"

    src_files=()
    pushd "$src_dir" >/dev/null
        src_files=($(find "$find_dir" -name "*$file_ext"))
    popd >/dev/null

    for src_file in "${src_files[@]}"; do
        src_file_path="$src_dir/$src_file"
        dst_file_path="$dst_dir/$src_file"
        dst_dir_path="$(dirname "$dst_file_path")"
        mkdir -p "$dst_dir_path"
        cp -f "$src_file_path" "$dst_file_path"
    done
}

function copy_libraries() {
    local rel_src_dir="$1"
    local rel_lib_dir="$2"

    if [ -d "$rel_lib_dir" ]; then
        rm -rf "$rel_lib_dir"
    fi
    mkdir -p "$rel_lib_dir"
    copy_specified_files "$rel_src_dir/src" "$rel_lib_dir" "." ".a"
    copy_specified_files "$rel_src_dir/src" "$rel_lib_dir" "." ".so"
    copy_specified_files "$rel_src_dir" "$rel_lib_dir" "external" ".a"
    copy_specified_files "$rel_src_dir" "$rel_lib_dir" "external" ".so"
}

if [ $# -lt 1 ]; then
    FATAL "You should specify the installing directory"
fi

rats_src_dir="$1"
script_dir="$(dirname "$0")"
install_dir="$script_dir/rats-tls"

if [ ! -d "$install_dir" ]; then
    mkdir "$install_dir"
else
    FATAL "It seems Rats-TLS has been installed in '$install_dir'"
fi

install_dir="$(readlink -f "$install_dir")"

include_dir="$install_dir/include"
lib_dir="$install_dir/lib"
cmake_dir="$install_dir/cmake"

## cmake directory
if [ -d "$cmake_dir" ]; then
    rm -rf "$cmake_dir"
fi
echo "Copying CMake files"
cp -r "$rats_src_dir/cmake" "$cmake_dir"

## header directory
if [ -d "$include_dir" ]; then
    rm -rf "$include_dir"
fi
echo "Copying header files"
cp -r "$rats_src_dir/src/include" "$include_dir"
copy_specified_files "$rats_src_dir/src" "$include_dir" "external" ".h"

## library directory
copying_flag=0
src_lib_dir="$rats_src_dir/Release-build"
if [ -d "$src_lib_dir" ]; then
    echo "Copying release library files"
    copy_libraries "$src_lib_dir" "$lib_dir/Release"
    copying_flag=$(($copying_flag+1))
fi
src_lib_dir="$rats_src_dir/Prerelease-build"
if [ -d "$src_lib_dir" ]; then
    echo "Copying prerelease library files"
    copy_libraries "$src_lib_dir" "$lib_dir/Prerelease"
    copying_flag=$(($copying_flag+1))
fi
src_lib_dir="$rats_src_dir/Debug-build"
if [ -d "$src_lib_dir" ]; then
    echo "Copying debug library files"
    copy_libraries "$src_lib_dir" "$lib_dir/Debug"
    copying_flag=$(($copying_flag+1))
fi
if [ $copying_flag -eq 0 ]; then
    FATAL "Failed to find any build directory"
fi