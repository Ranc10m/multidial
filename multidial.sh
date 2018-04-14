#!/bin/bash
#
# Dial multiple internet connection over a single interface

# Defaults
VTH="vth"
ETH="eth0"
USER="scu@edu"
PASSWORD=""
CONNECT_POLL=1
CONNECT_TIMEOUT=10
IPV6_PREFIX="2001:250:2003:2010:200:5efe"
REMOTE_ROUTER="202.115.39.98"
START_VTH_ID=1
START_ADDRESS="121.48.228.10"
GATEWAY="121.48.228.1"
NETMASK=24

ME=$(basename "$0")
# Must be root
if [ "$(/usr/bin/id -u)" != 0 ]; then
    echo "$ME: You must be root to run this script" >&2
    exit 1
fi

usage() {
    echo
}

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
    addresses=$(ip "$family" addr show "$ifname" 2>/dev/null |
        grep -o -E 'inet6?.*scope global' |
        sed 's/^inet6\{0,1\} *\([^ /]*\).*$/\1/')
    echo "$addresses"
}

# Create virtual interface for dial
# Args: [ifname]
# e.g. create_virtual_interface vth0
create_virtual_interface() {
    local ifname=$1
    ip link add link "$ETH" name "$ifname" type macvlan >/dev/null 2>&1 || return 1
}

# Remove virtual interface
# Args: [ifname]
# e.g. remove_virtual_interface vth0
remove_virtual_interface() {
    local ifname=$1
    ip link show "$ifname" >/dev/null 2>&1 || return
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
    ip link show | grep "$isatap_ifname" >/dev/null && return 1
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
    if ip link show | grep "$isatap_ifname" >/dev/null; then
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

# Clean all dial associated with the interface
# Args: [ifname]
# e.g. dial_clean_all vth0
dial_clean_all() {
    local ifname=$1
    pppoe_stop "$ifname"
    destroy_isatap_tunnel "$ifname"
    remove_virtual_interface "$ifname"
}

# PPPoE dial
# Args: [ifname] [--ipv6]
# e.g. pppoe_dial vth0 --ipv6
pppoe_dial() {
    local ifname=$1
    local linkname=ppp-$ifname
    local enable_ipv6=0
    local ppp_ifname
    if [ "$2" = "--ipv6" ]; then
        enable_ipv6=1
    fi
    if [ -z "$ifname" ]; then
        error "pppoe_dial: You must specify a interface"
        exit 1
    fi
    if [ -n "$(get_pppoe_ifname "$ifname")" ]; then
        error "pppoe_dial: There already seems to be a PPPoE connection up with $ifname"
        exit 1
    fi
    # The interface has not existed yet
    if ! ip link show "$ifname" >/dev/null 2>&1; then
        if ! create_virtual_interface "$ifname"; then
            error "pppoe_dial: Cannot create the interface"
            exit 1
        fi
        ip link set "$ifname" up
    fi
    if ! pppd plugin rp-pppoe.so "$ifname" linkname "$ifname" \
        persist hide-password noauth user "$USER" password "$PASSWORD" >/dev/null 2>&1; then
        remove_virtual_interface "$ifname"
        error "pppoe_dial: Cannot create PPPoE connection for $ifname"
        exit 1
    fi
    local TIME=0
    printf "Trying to create connection for %s " "$ifname"
    while true; do
        ppp_ifname=$(get_pppoe_ifname "$ifname")
        if [ -n "$ppp_ifname" ]; then
            local ipv4
            local ipv6
            ipv4=$(get_ip "$ppp_ifname" --ipv4)
            if [ -n "$ipv4" ]; then
                if [ "$enable_ipv6" = "1" ]; then
                    if ! build_isatap_tunnel "$ppp_ifname"; then
                        error "Cannot build isatap tunnel for $ifname"
                        exit 1
                    fi
                fi
                echo " Connected!"
                ipv6=$(get_ip isa-"$ppp_ifname" --ipv6)
                printf "ipv4:%s ipv6:%s\\n" "$ipv4" "$ipv6"
                return
            fi
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
    return 1
}

# DHCP dial
# Args: [ifname] [--ipv6]
# e.g. dhcp_dial vth0 --ipv6
dhcp_dial() {
    local ifname=$1
    local enable_ipv6=0
    if [ "$2" = "--ipv6" ]; then
        enable_ipv6=1
    fi
    if [ -z "$ifname" ]; then
        error "dhcp_dial: You must specify a interface"
        exit 1
    fi
    if [ -n "$(get_ip "$ifname" --ipv4)" ]; then
        error "dhcp_dial: There already seems to be a connection up with ($ifname)"
        exit 1
    fi
    # The interface has not existed yet
    if ! ip link show "$ifname" >/dev/null 2>&1; then
        if ! create_virtual_interface "$ifname"; then
            error "dhcp_dial: Cannot create the interface"
            exit 1
        fi
        ip link set "$ifname" up
    fi
    dhclient -nw "$ifname"
    local TIME=0
    printf "Trying to create connection for %s " "$ifname"
    while true; do
        local ipv4
        local ipv6
        ipv4=$(get_ip "$ifname" --ipv4)
        if [ -n "$ipv4" ]; then
            if [ "$enable_ipv6" = "1" ]; then
                if ! build_isatap_tunnel "$ifname"; then
                    error "Cannot build isatap tunnel for $ifname"
                    exit 1
                fi
            fi
            echo " Connected!"
            ipv6=$(get_ip isa-"$ifname" --ipv6)
            printf "ipv4:%s ipv6:%s\\n" "$ipv4" "$ipv6"
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
    return 1
}

# Static dial
# Args: [ifname] [ipv4 address] [netmask] [--ipv6]
# e.g. static_dial vth0 121.48.228.10 24 --ipv6
static_dial() {
    local ifname=$1
    local ipv4=$2
    local netmask=$3
    local enable_ipv6=0
    if [ "$4" = "--ipv6" ]; then
        enable_ipv6=1
    fi
    if [ -z "$ifname" ]; then
        error "static_dial: You must specify a interface"
        exit 1
    fi
    if [ -n "$(get_ip "$ifname" --ipv4)" ]; then
        error "static_dial: There already seems to be a connection up with ($ifname)"
        exit 1
    fi
    printf "Trying to create connection for %s ." "$ifname"
    # The interface has not existed yet
    if ! ip link show "$ifname" >/dev/null 2>&1; then
        if ! create_virtual_interface "$ifname"; then
            error "static_dial: Cannot create the interface"
            exit 1
        fi
        ip link set "$ifname" up
    fi
    if ip addr add "$ipv4"/"$netmask" dev "$ifname" >/dev/null 2>&1; then
        if [ "$enable_ipv6" = "1" ]; then
            if ! build_isatap_tunnel "$ifname"; then
                error "Cannot build isatap tunnel for $ifname"
                exit 1
            fi
        fi
        echo " Connected!"
        ipv6=$(get_ip isa-"$ifname" --ipv6)
        printf "ipv4:%s ipv6:%s\\n" "$ipv4" "$ipv6"
        return 0
    fi
    dial_clean_all "$ifname"
    echo " Failed!"
    return 1
}

# Output next virtual interface id
# Args: none
# e.g. get_next_vth_id
get_next_vth_id() {
    while true; do
        ip link show "${VTH}${START_VTH_ID}" >/dev/null 2>&1 || break
        START_VTH_ID=$((START_VTH_ID + 1))
    done
    echo "$START_VTH_ID"
}

# Output next static address
# Args: none
# e.g. get_next_address
get_next_address() {
    while true; do
        local a=()
        local i=0
        ip -4 addr show | grep "$START_ADDRESS" >/dev/null || break
        for n in $(echo "$START_ADDRESS" | tr '.' ' '); do
            a["$i"]=$n
            i=$((i + 1))
        done
        a[3]=$((a[3] + 1))
        START_ADDRESS=$(echo "${a[@]}" | tr ' ' '.')
    done
    echo "$START_ADDRESS"
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
        if pppoe_dial "${VTH}${vth_id}" "$enable_ipv6"; then
            ifname=$(get_pppoe_ifname "${VTH}${vth_id}")
            gateway=$(get_pppoe_gateway "${VTH}${vth_id}")
            ipv4=$(get_ip "$ifname" --ipv4)
            configure_routing_table "$ifname" "$vth_id" "$ipv4" "$gateway"
        fi
        pppoe_num=$((pppoe_num - 1))
    done
    # dhcp dial
    while [ "$dhcp_num" -gt 0 ]; do
        vth_id=$(get_next_vth_id)
        pppoe_dial "${VTH}${vth_id}" "$enable_ipv6"
        dhcp_num=$((dhcp_num - 1))
    done
    # static dial
    while [ "$static_num" -gt 0 ]; do
        vth_id=$(get_next_vth_id)
        ipv4=$(get_next_address)
        netmask="$NETMASK"
        static_dial "${VTH}${vth_id}" "$ipv4" "$netmask" "$enable_ipv6"
        static_num=$((static_num - 1))
    done
}

bulk_dial_clean() {
    for i in $(ip link show | grep -E -o 'vth[0-9]{0,3}'); do
        dial_clean_all "$i"
    done
}

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
