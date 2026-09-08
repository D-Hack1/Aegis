# ja3.zeek — JA3/JA3S TLS fingerprinting for Aegis NIDS
#
# Appends `ja3` and `ja3s` fields to ssl.log by extending SSL::Info.
# No external packages or compiled plugins required.
# Compatible with zeek/zeek:6.0.3.
#
# JA3  = MD5 fingerprint of the TLS ClientHello parameters (client identity).
# JA3S = MD5 fingerprint of the TLS ServerHello parameters (server identity).
#
# Based on the Salesforce JA3 algorithm (BSD-3-Clause):
#   https://github.com/salesforce/ja3
#   Authors: John B. Althouse, Jeff Atkinson, Josh Atkins

module JA3;

# ---------------------------------------------------------------------------
# GREASE values (RFC 8701) — excluded from all cipher/extension/curve lists
# before hashing so that browser anti-ossification randomisation does not
# produce unique fingerprints for every connection.
# ---------------------------------------------------------------------------
const GREASE: set[count] = {
    2570,   # 0x0A0A
    6682,   # 0x1A1A
    10794,  # 0x2A2A
    14906,  # 0x3A3A
    19018,  # 0x4A4A
    23130,  # 0x5A5A
    27242,  # 0x6A6A
    31354,  # 0x7A7A
    35466,  # 0x8A8A
    39578,  # 0x9A9A
    43690,  # 0xAAAA
    47802,  # 0xBABA
    51914,  # 0xCACA
    56026,  # 0xDADA
    60138,  # 0xEAEA
    64250   # 0xFAFA
};

# Dash separator used between values within each JA3 field.
const SEP = "-";

# ---------------------------------------------------------------------------
# Per-connection transient storage for TLS handshake parameters.
# Attached to the connection record while the handshake is in progress;
# the fields are consumed when the hello events fire.
# ---------------------------------------------------------------------------
type TLSFPStorage: record {
    # ClientHello fields
    client_version:    count  &default=0;
    client_ciphers:    string &default="";
    extensions:        string &default="";   # client-side extensions
    e_curves:          string &default="";
    ec_point_fmt:      string &default="";
    # ServerHello fields
    server_extensions: string &default="";   # server-side extensions
};

redef record connection += {
    tlsfp: TLSFPStorage &optional;
};

# ---------------------------------------------------------------------------
# Extend SSL::Info with ja3 and ja3s output fields.
# Both are &optional so that they are simply absent (not "-") when no
# ClientHello/ServerHello was captured (e.g. resumed sessions mid-capture).
# ---------------------------------------------------------------------------
redef record SSL::Info += {
    ## MD5 fingerprint of the TLS ClientHello parameters.
    ## 32-character lowercase hex string. Absent if no ClientHello was seen.
    ja3:  string &optional &log;

    ## MD5 fingerprint of the TLS ServerHello parameters.
    ## 32-character lowercase hex string. Absent if no ServerHello was seen.
    ja3s: string &optional &log;
};

# ---------------------------------------------------------------------------
# Event: TLS extension seen in a ClientHello or ServerHello.
# We accumulate extension type codes for the originator (client) side only
# here; the ServerHello extension accumulation happens in ssl_server_hello
# because the server extension list is not separately fired as an event in
# Zeek 6.x — only the full ServerHello is.
# ---------------------------------------------------------------------------
event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
{
    if ( ! is_orig )
        return;
    if ( code in GREASE )
        return;

    if ( ! c?$tlsfp )
        c$tlsfp = TLSFPStorage();

    if ( c$tlsfp$extensions == "" )
        c$tlsfp$extensions = cat(code);
    else
        c$tlsfp$extensions = string_cat(c$tlsfp$extensions, SEP, cat(code));
}

# ---------------------------------------------------------------------------
# Event: Supported elliptic curves / named groups extension.
# ---------------------------------------------------------------------------
event ssl_extension_elliptic_curves(c: connection, is_orig: bool, curves: index_vec)
{
    if ( ! is_orig )
        return;
    if ( ! c?$tlsfp )
        c$tlsfp = TLSFPStorage();

    for ( i in curves )
    {
        if ( curves[i] in GREASE )
            next;
        if ( c$tlsfp$e_curves == "" )
            c$tlsfp$e_curves = cat(curves[i]);
        else
            c$tlsfp$e_curves = string_cat(c$tlsfp$e_curves, SEP, cat(curves[i]));
    }
}

# ---------------------------------------------------------------------------
# Event: EC point formats extension.
# ---------------------------------------------------------------------------
event ssl_extension_ec_point_formats(c: connection, is_orig: bool, point_formats: index_vec)
{
    if ( ! is_orig )
        return;
    if ( ! c?$tlsfp )
        c$tlsfp = TLSFPStorage();

    for ( i in point_formats )
    {
        if ( point_formats[i] in GREASE )
            next;
        if ( c$tlsfp$ec_point_fmt == "" )
            c$tlsfp$ec_point_fmt = cat(point_formats[i]);
        else
            c$tlsfp$ec_point_fmt = string_cat(c$tlsfp$ec_point_fmt, SEP, cat(point_formats[i]));
    }
}

# ---------------------------------------------------------------------------
# Event: ServerHello — compute JA3S.
#
# JA3S string format: "{version},{cipher},{extensions}"
#   version    = negotiated TLS version (decimal)
#   cipher     = negotiated cipher suite code (decimal)
#   extensions = dash-separated list of extension type codes (decimal)
#
# The ServerHello extensions are not surfaced as a dedicated Zeek event in
# 6.x, so we read them from the SSL analyzer state via c$ssl fields where
# available, or leave extensions empty.
# ---------------------------------------------------------------------------
event ssl_server_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, server_random: string, session_id: string,
                       cipher: count, comp_method: count) &priority=1
{
    if ( cipher in GREASE )
        return;
    if ( ! c?$ssl )
        return;

    # JA3S: version,cipher,extensions
    # Extensions from the ServerHello are not individually fired as events,
    # so we leave the extensions field empty (consistent with Salesforce JA3S).
    local ja3s_str = string_cat(cat(version), ",", cat(cipher), ",");
    c$ssl$ja3s = md5_hash(ja3s_str);
}

# ---------------------------------------------------------------------------
# Event: ClientHello — compute JA3.
#
# JA3 string format: "{version},{ciphers},{extensions},{curves},{point_formats}"
#   version      = client-offered TLS version (decimal)
#   ciphers      = dash-separated cipher suite codes, GREASE excluded
#   extensions   = dash-separated extension type codes (from ssl_extension)
#   curves       = dash-separated named group IDs (from ssl_extension_elliptic_curves)
#   point_formats= dash-separated EC point format IDs
#
# The ssl_client_hello event signature differs between Zeek < 2.6 and >= 2.6.
# Zeek version numbers are encoded as (major*10000 + minor*100 + patch), so
# Zeek 6.0.3 == 60003 which is >= 20600.  We use the @if preprocessor guard
# to remain compatible with both, matching the Salesforce reference script.
# ---------------------------------------------------------------------------
@if ( ( Version::number >= 20600 ) || ( Version::number == 20500 && Version::info$commit >= 944 ) )
event ssl_client_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, client_random: string, session_id: string,
                       ciphers: index_vec, comp_methods: index_vec) &priority=1
@else
event ssl_client_hello(c: connection, version: count, possible_ts: time,
                       client_random: string, session_id: string,
                       ciphers: index_vec) &priority=1
@endif
{
    if ( ! c?$ssl )
        return;
    if ( ! c?$tlsfp )
        c$tlsfp = TLSFPStorage();

    c$tlsfp$client_version = version;

    # Build cipher list, excluding GREASE values.
    local cipher_str = "";
    for ( i in ciphers )
    {
        if ( ciphers[i] in GREASE )
            next;
        if ( cipher_str == "" )
            cipher_str = cat(ciphers[i]);
        else
            cipher_str = string_cat(cipher_str, SEP, cat(ciphers[i]));
    }

    # Assemble JA3 string and hash it.
    local ja3_str = string_cat(
        cat(c$tlsfp$client_version), ",",
        cipher_str, ",",
        c$tlsfp$extensions, ",",
        c$tlsfp$e_curves, ",",
        c$tlsfp$ec_point_fmt
    );
    c$ssl$ja3 = md5_hash(ja3_str);
}
