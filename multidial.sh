#!/bin/bash
#
# Copyright 2017-2018 Ranc10m <xiayjchn@gmail.com>
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

# Available dial method
METHODS=('pppoe' 'dhcp' 'static')

# PPPoE configuration
USER="scu@edu"
PASSWORD=""

# ISATAP configuration
REMOTE_ROUTER="202.115.39.98"
IPV6_PREFIX="2001:250:2003:2010:200:5efe"
IPV6_GATEWAY="$IPV6_PREFIX:$REMOTE_ROUTER"

# Static IP address
ADDRESS="121.48.228.10"
GATEWAY="121.48.228.1"
NETMASK=24

error() {
    echo "error: $*" >&2
}

# Must be root
if [ "$(/usr/bin/id -u)" != 0 ]; then
    error "You must be root to run this script"
    exit 1
fi

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
    touch "$DATA_DIR/$ifname"
}

# Remove virtual interface
# Args: [ifname]
# e.g. remove_virtual_interface vth0
remove_virtual_interface() {
    local ifname=$1
    ip link show "$ifname" >/dev/null 2>&1 || return
    [ -f "$DATA_DIR/$ifname" ] && rm -f "$DATA_DIR/$ifname" 2>/dev/null
    if ip link show "$ifname" | grep "$ifname@$ETH" >/dev/null; then
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
    gateway=$(ip -4 addr show "$ppp_ifname" 2>/dev/null | grep -o 'peer *[0-9\.]*' | awk '{print $2}')
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
    echo
}

# Configure routing table
# Args: [ifname] [table_id] [ip address] [gateway]
# e.g. configure_routing_table vth1 1 121.48.228.11 121.48.228.1
configure_routing_table() {
    local ifname=$1
    local table_id=$2
    local ip=$3
    local gateway=$4
    [ -n "$ifname" ] && [ -n "$table_id" ] && [ -n "$ip" ] && [ -n "$gateway" ] && return 1
    ip route add default via "$gateway" dev "$ifname" table "$table_id"
    ip rule add from "$ip" table "$table_id"
}

# Configure routing table
# Args: [ifname]
# e.g. delete_routing_table 1
remove_routing_table() {
    local table_id=$2

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
                echo "gateway:${gateway}"
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
    dhclient -nw "$ifname"
    local TIME=0
    printf "Trying to create connection for %s " "$ifname"
    while true; do
        ipv4=$(get_ip "$ifname" --ipv4)
        gateway=$(get_dhcp_gateway "$ifname")
        if [ -n "$ipv4" ]; then
            {
                echo "ifname:${ifname}"
                echo "ipv4:${ipv4}"
                echo "gateway:${gateway}"
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
            echo "gateway:${GATEWAY}"
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
    ifname2=$(grep ifname <"$DATA_DIR/$ifname" | cut -d ':' -f 2)
    [ "$enable_ipv6" = '1' ] && build_isatap_tunnel "$ifname2"
    ipv4=$(get_ip "$ifname2" --ipv4)
    ipv6=$(get_ip isa-"$ifname2" --ipv6)
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
        ip -4 addr show | grep "$_cur_address" >/dev/null || break
        for n in $(echo "$_cur_address" | tr '.' ' '); do
            a["$i"]=$n
            i=$((i + 1))
        done
        a[3]=$((a[3] + 1))
        _cur_address=$(echo "${a[@]}" | tr ' ' '.')
    done
    echo "$_cur_address"
}

bulk_dial() {
    local optname
    local vth_id
    local ifname
    local gateway
    local pppoe_num=0
    local dhcp_num=0
    local static_num=0
    local enable_ipv6=''
    while getopts ":p:d:s:6" optname; do
        case "$optname" in
        "p")
            pppoe_num=$OPTARG
            ;;
        "d")
            dhcp_num=$OPTARG
            ;;
        "s")
            static_num=$OPTARG
            ;;
        "6")
            enable_ipv6='--ipv6'
            ;;
        "?")
            echo "Unknown option $OPTARG" >&2
            exit 1
            ;;
        ":")
            echo "No argument value for option $OPTARG" >&2
            exit 1
            ;;
        "*")
            # Should not occur
            echo "Unknown error while processing options" >&2
            exit 1
            ;;
        esac
    done
    #pppoe dial
    while [ "$pppoe_num" -gt 0 ]; do
        vth_id=$(get_next_vth_id)
        dial_helper "pppoe" "${VTH}${vth_id}" "$enable_ipv6"
        pppoe_num=$((pppoe_num - 1))
    done
    # dhcp dial
    while [ "$dhcp_num" -gt 0 ]; do
        vth_id=$(get_next_vth_id)
        dial_helper "dhcp" "${VTH}${vth_id}" "$enable_ipv6"
        dhcp_num=$((dhcp_num - 1))
    done
    # static dial
    while [ "$static_num" -gt 0 ]; do
        vth_id=$(get_next_vth_id)
        ipv4=$(get_next_address)
        netmask="$NETMASK"
        dial_helper "static" "${VTH}${vth_id}" "$ipv4" "$netmask" "$enable_ipv6"
        static_num=$((static_num - 1))
    done
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
    pppoe_stop "$ifname"
    destroy_isatap_tunnel "$ifname"
    remove_virtual_interface "$ifname"
}

bulk_dial_clean() {
    for i in $DATA_DIR/*; do
        [ -f "$i" ] || break
        dial_clean_all "$(basename "$i")" >/dev/null 2>&1
    done
    for i in $(ip link show | grep -E -o 'vth[0-9]{0,3}'); do
        dial_clean_all "$i" >/dev/null 2>&1
    done
}

main() {
    [ ! -d "$DATA_DIR" ] && mkdir -p "$DATA_DIR"
    case "$1" in
    -i)
        ifname=$2
        pppoe_dial "$ifname"
        ;;
    -r)
        ifname=$2
        dial_clean_all "$ifname"
        ;;
    -c)
        bulk_dial_clean
        ;;
    *)
        bulk_dial "$@"
        ;;
    esac
}

main "$@"
