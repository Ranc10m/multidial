#!/bin/bash
#
# Copyright (c) 2018 Yujie Xia <xiayjchn@gmail.com>
#
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# Defaults
VTH="vth"
ETH="eth0"
CONNECT_POLL=1
CONNECT_TIMEOUT=10
DATA_DIR='/tmp/multidial'
MAXCONN=100

# Available dial method
METHODS=('pppoe' 'dhcp' 'static')

# PPPoE configuration
USER="scu@edu"
PASSWORD=""

# ISATAP configuration
REMOTE_ROUTER="202.115.39.98"
IPV6_PREFIX="2001:250:2003:2010:200:5efe"
IPV6_GATEWAY="2001:250:2003:2010:200:5efe:ca73:2762"

# Static IP address
ADDRESS="121.48.228.21"
GATEWAY="121.48.228.1"
NETMASK=24

error() {
    echo "error: $*" >&2
}

# Output IP addresses on the interface
# Args: [ifname] [--ipv4|ipv4]
# e.g. get_ip vth0 --ipv4
get_ip() {
    local ifname=$1
    local family
    [ "$2" = "--ipv4" ] && family='-4'
    [ "$2" = "--ipv6" ] && family='-6'
    local addresses
    addresses=$(ip $family addr show "$ifname" 2>/dev/null |
        grep -o -E 'inet6?.*scope global' |
        sed 's/^inet6\{0,1\} *\([^ /]*\).*$/\1/')
    echo "$addresses"
}

# Create virtual interface for dial
# Args: [ifname]
# e.g. create_virtual_interface vth0
create_virtual_interface() {
    local ifname=$1
    [ -f "$DATA_DIR/$ifname" ] && rm -f "$DATA_DIR/$ifname" 2>/dev/null
    ip link add link "$ETH" name "$ifname" type macvlan >/dev/null 2>&1 || return 1
    echo "eth:$ETH" >>"$DATA_DIR/$ifname"
}

# Remove virtual interface
# Args: [ifname]
# e.g. remove_virtual_interface vth0
remove_virtual_interface() {
    local ifname=$1
    local eth
    ip link show "$ifname" >/dev/null 2>&1 || return
    eth=$(grep "^eth:" <"$DATA_DIR/$ifname" | sed 's/^eth://')
    [ -f "$DATA_DIR/$ifname" ] && rm -f "$DATA_DIR/$ifname" 2>/dev/null
    if ip link show "$ifname" | grep "$ifname@$eth" >/dev/null; then
        ip link set "$ifname" down
        ip link del "$ifname"
    fi
}

# Build a isatap tunnel
# Args: [ifname]
# e.g. build_isatap_tunnel vth0
build_isatap_tunnel() {
    local ifname=$1
    local isatap_ifname=isa-"$ifname"
    local ipv4
    ipv4=$(get_ip "$ifname" --ipv4)
    [ -z "$ipv4" ] && return 1
    ip link show "$isatap_ifname" >/dev/null 2>&1 && return 1
    ip tunnel add "$isatap_ifname" mode sit remote "$REMOTE_ROUTER" local "$ipv4"
    ip link set dev "$isatap_ifname" up
    ip -6 addr add "$IPV6_PREFIX:$ipv4"/64 dev "$isatap_ifname"
}

# Destroy a isatap tunnel
# Args: [ifname]
# e.g. destroy_isatap_tunnel vth0
destroy_isatap_tunnel() {
    local ifname=$1
    local isatap_ifname=isa-"$ifname"
    if ip link show "$isatap_ifname" >/dev/null 2>&1; then
        ip link set "$isatap_ifname" down
        ip tunnel del "$isatap_ifname"
    fi
}

# Output pppoe dial ifname
# Args: [ifname]
# e.g. get_pppoe_ifname vth0
get_pppoe_ifname() {
    local ifname=$1
    local linkname=ppp-$ifname
    local ppp_ifname
    [ -f "/var/run/$linkname.pid" ] && ppp_ifname=$(sed -n '2p' <"/var/run/$linkname.pid")
    [ -f "/etc/ppp/$linkname.pid" ] && ppp_ifname=$(sed -n '2p' <"/etc/ppp/$linkname.pid")
    echo "$ppp_ifname"
}

# Output dhcp dial ifname
# Args: [ifname]
# e.g. get_dhcp_gateway vth0
get_dhcp_gateway() {
    local ifname=$1
    local gateway
    gateway=$(ip -4 route |
        grep "^[0-9\\./]* .*${ifname}" |
        sed "s/\\(^[0-9\\.]*\\).*$/\\1/" |
        sed 's/0$/1/')
    echo "$gateway"
}

# Output pppoe dial gateway
# Args: [ifname]
# e.g. get_pppoe_gateway vth0
get_pppoe_gateway() {
    local ifname=$1
    local ppp_ifname
    local gateway
    ppp_ifname=$(get_pppoe_ifname "$ifname")
    gateway=$(ip -4 addr show "$ppp_ifname" 2>/dev/null |
        grep -o 'peer *[0-9\.]*' | awk '{print $2}')
    echo "$gateway"
}

# Stop pppoe dial
# Args: [ifname]
# e.g. pppoe_stop vth0
pppoe_stop() {
    local ifname=$1
    local linkname=ppp-$ifname
    local ppp_ifname
    local pppd_id
    ppp_ifname=$(get_pppoe_ifname "$ifname")
    [ -n "$ppp_ifname" ] && destroy_isatap_tunnel "$ppp_ifname"
    [ -f "/var/run/$linkname.pid" ] && pppd_id=$(sed -n '1p' <"/var/run/$linkname.pid")
    [ -f "/etc/ppp/$linkname.pid" ] && pppd_id=$(sed -n '1p' <"/etc/ppp/$linkname.pid")
    [ -n "$pppd_id" ] && kill "$pppd_id" >/dev/null 2>&1
}

# Output a unused a routing table id
# Args: none
# e.g. get_empty_routing_table
get_empty_routing_table() {
    [ -z "$_cur_table_id" ] && _cur_table_id=1
    while true; do
        [ -z "$(ip -4 route show table ${_cur_table_id})" ] &&
            [ -z "$(ip -6 route show table ${_cur_table_id})" ] &&
            break
        _cur_table_id=$((_cur_table_id + 1))
    done
    while ip -4 rule del table "$_cur_table_id" >/dev/null 2>&1; do true; done
    while ip -6 rule del table "$_cur_table_id" >/dev/null 2>&1; do true; done
    echo "$_cur_table_id"
}

# Configure routing table
# Args: [ifname] [table_id] [ip address] [gateway]
# e.g. configure_routing_table vth1 1 121.48.228.11 121.48.228.1
configure_routing_table() {
    local ifname=$1
    local ipv4
    local ipv6
    local ifname2
    local gateway4
    local gateway6
    local table_id
    ifname2=$(grep "^ifname:" <"$DATA_DIR/$ifname" | sed 's/^ifname://')
    ipv4=$(grep "^ipv4:" <"$DATA_DIR/$ifname" | sed 's/^ipv4://')
    ipv6=$(grep "^ipv6:" <"$DATA_DIR/$ifname" | sed 's/^ipv6://')
    gateway4=$(grep "^gateway4:" <"$DATA_DIR/$ifname" | sed 's/^gateway4://')
    gateway6=$(grep "^gateway6:" <"$DATA_DIR/$ifname" | sed 's/^gateway6://')
    table_id=$(get_empty_routing_table)
    echo "table_id:${table_id}" >>"$DATA_DIR/$ifname"
    if [ -n "$ipv4" ]; then
        ip -4 route add default via "$gateway4" dev "$ifname2" table "$table_id"
        ip -4 rule add from "$ipv4" table "$table_id"
    fi
    if [ -n "$ipv6" ]; then
        ip -6 route add default via "$gateway6" dev "isa-${ifname2}" table "$table_id"
        ip -6 rule add from "$ipv6" table "$table_id"
    fi
}

# Configure routing table
# Args: [ifname]
# e.g. remove_routing_table vth0
remove_routing_table() {
    local ifname=$1
    local table_id
    table_id=$(grep "^table_id:" <"$DATA_DIR/$ifname" | sed 's/^table_id://')
    if [ -n "$table_id" ]; then
        ip -4 route del default table "$table_id" >/dev/null 2>&1
        ip -6 route del default table "$table_id" >/dev/null 2>&1
        while ip -4 rule del table "$table_id" >/dev/null 2>&1; do true; done
        while ip -6 rule del table "$table_id" >/dev/null 2>&1; do true; done
    fi
}

# PPPoE dial
# Args: [ifname]
# e.g. pppoe_dial vth0
pppoe_dial() {
    local ifname=$1
    local linkname=ppp-$ifname
    local ppp_ifname
    local ipv4
    local gateway
    if ! pppd plugin rp-pppoe.so "$ifname" linkname "$ifname" \
        persist hide-password noauth user "$USER" password "$PASSWORD" >/dev/null 2>&1; then
        dial_clean_all "$ifname"
        error "pppoe_dial: Cannot create PPPoE connection for $ifname"
        exit 1
    fi
    local TIME=0
    printf "Trying to create connection for %s " "$ifname"
    while true; do
        ppp_ifname=$(get_pppoe_ifname "$ifname")
        ipv4=$(get_ip "$ppp_ifname" --ipv4)
        if [ -n "$ppp_ifname" ] && [ -n "$ipv4" ]; then
            gateway=$(get_pppoe_gateway "$ifname")
            {
                echo "ifname:${ppp_ifname}"
                echo "ipv4:${ipv4}"
                echo "gateway4:${gateway}"
            } >>"$DATA_DIR/$ifname"
            echo " Connected!"
            return
        fi
        printf .
        sleep $CONNECT_POLL
        TIME=$((TIME + CONNECT_POLL))
        if [ $TIME -gt $CONNECT_TIMEOUT ]; then
            break
        fi
    done
    dial_clean_all "$ifname"
    echo " Failed!"
    exit 1
}

# DHCP dial
# Args: [ifname]
# e.g. dhcp_dial vth0
dhcp_dial() {
    local ifname=$1
    local ipv4
    local gateway
    dhclient -nw "$ifname" || exit 1
    local TIME=0
    printf "Trying to create connection for %s " "$ifname"
    while true; do
        ipv4=$(get_ip "$ifname" --ipv4)
        gateway=$(get_dhcp_gateway "$ifname")
        if [ -n "$ipv4" ]; then
            {
                echo "ifname:${ifname}"
                echo "ipv4:${ipv4}"
                echo "gateway4:${gateway}"
            } >>"$DATA_DIR/$ifname"
            echo " Connected!"
            return
        fi
        printf .
        sleep $CONNECT_POLL
        TIME=$((TIME + CONNECT_POLL))
        if [ $TIME -gt $CONNECT_TIMEOUT ]; then
            break
        fi
    done
    dial_clean_all "$ifname"
    echo " Failed!"
    exit 1
}

# Static dial
# Args: [ifname] [ipv4 address] [netmask]
# e.g. static_dial vth0 121.48.228.10 24
static_dial() {
    local ifname=$1
    local ipv4=$2
    local netmask=$3
    printf "Trying to create connection for %s ." "$ifname"
    if ip addr add "$ipv4"/"$netmask" dev "$ifname" >/dev/null 2>&1; then
        {
            echo "ifname:${ifname}"
            echo "ipv4:${ipv4}"
            echo "gateway4:${GATEWAY}"
        } >>"$DATA_DIR/$ifname"
        echo " Connected!"
        return 0
    fi
    dial_clean_all "$ifname"
    echo " Failed!"
    exit 1
}

# A unified dial function
# Args: [method] [ifname] ... [--ipv6]
# dial_helper pppoe vth0 ...
dial_helper() {
    local method=$1
    local ifname=$2
    local enable_ipv6=0
    if [ "${!#}" = "--ipv6" ]; then
        enable_ipv6=1
    fi
    shift 2
    local valid=0
    for m in "${METHODS[@]}"; do
        if [ "$method" = "$m" ]; then
            valid=1
            break
        fi
    done
    if [ "$valid" != "1" ]; then
        error "dial_helper: Method \"$method\" is not supported"
        exit 1
    fi
    if [ -z "$ifname" ]; then
        error "dial_helper: You must specify a interface"
        exit 1
    fi
    # The interface has not existed yet
    if ip link show "$ifname" >/dev/null 2>&1; then
        error "dial_helper: There already seems to be a connection up with ($ifname)"
        exit 1
    fi
    if ! create_virtual_interface "$ifname"; then
        error "dial_helper: Cannot create the interface"
        exit 1
    fi
    ip link set "$ifname" up
    "${method}_dial" "$ifname" "$@"
    local ifname2
    local ipv4
    local ipv6
    ifname2=$(grep "^ifname:" <"$DATA_DIR/$ifname" | sed 's/^ifname://')
    [ "$enable_ipv6" = '1' ] && build_isatap_tunnel "$ifname2"
    ipv4=$(get_ip "$ifname2" --ipv4)
    ipv6=$(get_ip isa-"$ifname2" --ipv6)
    if [ -n "$ipv6" ]; then
        {
            echo "ipv6:${ipv6}"
            echo "gateway6:${IPV6_GATEWAY}"
        } >>"$DATA_DIR/$ifname"
    fi
    configure_routing_table "$ifname"
    printf "ipv4:%s ipv6:%s\\n" "$ipv4" "$ipv6"
}

# Output next virtual interface id
# Args: none
# e.g. get_next_vth_id
get_next_vth_id() {
    [ -z "$_cur_vth_id" ] && _cur_vth_id=1
    while true; do
        ip link show "${VTH}${_cur_vth_id}" >/dev/null 2>&1 || break
        _cur_vth_id=$((_cur_vth_id + 1))
    done
    echo "${_cur_vth_id}"
}

# Output next static address
# Args: none
# e.g. get_next_address
get_next_address() {
    [ -z "$_cur_address" ] && _cur_address="$ADDRESS"
    while true; do
        local a=()
        local i=0
        [ -z "$(ip -4 addr show to "$_cur_address")" ] && break
        for n in $(echo "$_cur_address" | tr '.' ' '); do
            a["$i"]=$n
            i=$((i + 1))
        done
        a[3]=$((a[3] + 1))
        _cur_address=$(echo "${a[@]}" | tr ' ' '.')
    done
    echo "$_cur_address"
}

# Create connections in batches
# Args: [method] [number] [--ipv6]
# e.g. batch_dial pppoe 10 --ipv6
batch_dial() {
    local method=$1
    local number=$2
    local enable_ipv6=$3
    local vth_id
    local ipv4
    local netmask
    case "$method" in
    "pppoe" | "dhcp")
        while [ "$number" -gt 0 ]; do
            vth_id=$(get_next_vth_id)
            dial_helper "$method" "${VTH}${vth_id}" "$enable_ipv6"
            number=$((number - 1))
        done
        ;;
    "static")
        while [ "$number" -gt 0 ]; do
            vth_id=$(get_next_vth_id)
            ipv4=$(get_next_address)
            netmask="$NETMASK"
            dial_helper "$method" "${VTH}${vth_id}" "$ipv4" "$netmask" "$enable_ipv6"
            number=$((number - 1))
        done
        ;;
    esac
}

# Clean all dial associated with the interface
# Args: [ifname]
# e.g. dial_clean_all vth0
dial_clean_all() {
    local ifname=$1
    if [ -z "$ifname" ]; then
        error "You must specify a interface"
        return 1
    fi
    if ! ip link show "$ifname" >/dev/null 2>&1; then
        error "Interface \"$ifname\" does not exist"
        return 1
    fi
    pgrep -f "dhclient -nw $ifname" | xargs kill 2>/dev/null
    remove_routing_table "$ifname"
    destroy_isatap_tunnel "$ifname"
    pppoe_stop "$ifname"
    remove_virtual_interface "$ifname"
}

# Clean all connections in batches
# Args: none
# e.g. batch_dial_clean
batch_dial_clean() {
    for i in "$DATA_DIR"/*; do
        [ -f "$i" ] || break
        dial_clean_all "$(basename "$i")" >/dev/null 2>&1
    done
    for i in $(ip link show | grep -E -o 'vth[0-9]{0,3}'); do
        dial_clean_all "$i" >/dev/null 2>&1
    done
}

# Show all ip addresses over the all interfaces
# Args: none
# e.g. show_all_ip
show_all_ip() {
    find $DATA_DIR/ -maxdepth 1 -type f -print0 | xargs -0 grep ipv4 | sed 's/^.*ipv4://'
    find $DATA_DIR/ -maxdepth 1 -type f -print0 | xargs -0 grep ipv6 | sed 's/^.*ipv6://'
}

usage() {
    echo "Usage: multidial [OPTION]"
    echo "This shell script provide help to dial multiple internet connection over a single interface."
    echo "OPTIONS:"
    echo "    -p <n>               Make n distinct pppoe dial connections"
    echo "    -d <n>               Make n distinct dhcp dial connections"
    echo "    -s <n>               Make n distinct static dial connections"
    echo "    -6                   Enable ipv6, get ipv6 addresses through isatap tunnel"
    echo "    -i <interface>       Specify a real interface, default: eth0"
    echo "    -r <interface>       Remove all connections over this interface"
    echo "    -c                   Remove all connections over all virtual interfaces"
    echo "    -l                   List all ipv4 and ipv6 addresses"
    echo "    -h                   Print this message"
}

main() {
    local optname
    local pppoe_num
    local dhcp_num
    local static_num
    local enable_ipv6
    local clean_args
    # make sure the data dir exists
    [ ! -d "$DATA_DIR" ] && mkdir -p "$DATA_DIR"
    while getopts ":p:d:s:6i:r:chl" optname; do
        case "$optname" in
        "p")
            pppoe_num="$OPTARG"
            if ! [ "$pppoe_num" -le "$MAXCONN" ] 2>/dev/null; then
                error "Connection num should be in [0-$MAXCONN]"
                exit 1
            fi
            ;;
        "d")
            dhcp_num="$OPTARG"
            if ! [ "$dhcp_num" -le 100 ] 2>/dev/null; then
                error "Connection num should be in [0-$MAXCONN]"
                exit 1
            fi
            ;;
        "s")
            static_num="$OPTARG"
            if ! [ "$static_num" -le 100 ] 2>/dev/null; then
                error "Connection num should be in [0-$MAXCONN]"
                exit 1
            fi
            ;;
        "6")
            enable_ipv6='--ipv6'
            ;;
        "i")
            ETH="$OPTARG"
            if ! ip link show "$ETH" >/dev/null 2>&1; then
                error "Interface ${ETH} does not exist, you must specify a existed interface"
                exit 1
            fi
            ;;

        "r")
            clean_args="$OPTARG"
            ;;
        "c")
            clean_args="all"
            ;;
        "l")
            if [ "$#" != "1" ] || [ "$1" != "-l" ]; then
                error "invalid arguments"
                exit 1
            fi
            show_all_ip
            exit 0
            ;;
        "h")
            usage
            exit 0
            ;;
        "?")
            error "Unknown option $OPTARG"
            exit 1
            ;;
        ":")
            error "No argument value for option $OPTARG"
            exit 1
            ;;
        "*")
            # Should not occur
            echo "Unknown error while processing options" >&2
            exit 1
            ;;
        esac
    done
    if [ -z "${pppoe_num}${dhcp_num}${static_num}${enable_ipv6}${clean_args}" ]; then
        if [ -n "$*" ]; then
            error "invalid arguments: $*"
        else
            usage >&2
        fi
        exit 1
    fi
    # Must be root
    if [ "$(/usr/bin/id -u)" != 0 ]; then
        error "You must be root to run this script"
        exit 1
    fi
    if [ -n "$clean_args" ]; then
        if [ "$clean_args" = "all" ]; then
            batch_dial_clean
        else
            dial_clean_all "$clean_args" || exit 1
        fi
        exit 0
    fi
    [ -n "$pppoe_num" ] && batch_dial "pppoe" "$pppoe_num" "$enable_ipv6"
    [ -n "$dhcp_num" ] && batch_dial "dhcp" "$dhcp_num" "$enable_ipv6"
    [ -n "$static_num" ] && batch_dial "static" "$static_num" "$enable_ipv6"
    exit 0
}

main "$@"
