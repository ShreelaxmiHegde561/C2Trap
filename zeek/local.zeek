# Zeek Local Configuration for C2Trap
# Simplified for Zeek 8.x with JSON logging

# ===== Core Settings =====
# Output all logs in JSON format for easy parsing
@load policy/tuning/json-logs

# ===== Protocol Analyzers =====
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ftp
@load base/protocols/smtp
@load base/protocols/ssl
@load base/protocols/conn

# ===== Intel Framework =====
@load base/frameworks/intel
@load base/frameworks/notice

# ===== Startup Event =====
event zeek_init() {
    print "[C2Trap] Zeek Monitor Initialized";
    print fmt("[C2Trap] Logging to: %s", Log::default_dir);
}

# ===== Custom C2 Detection Notice =====
module C2Trap;

export {
    redef enum Notice::Type += {
        Suspicious_Beacon,
        Known_C2_Domain,
        Unusual_Port
    };
}

# Flag suspicious HTTP endpoints commonly used by C2
event http_request(c: connection, method: string, original_URI: string, 
                   unescaped_URI: string, version: string) {
    local suspicious_paths = /\/(beacon|gate|c2|cmd|update|check|submit|api\/beacon)/;
    
    if (suspicious_paths in unescaped_URI) {
        NOTICE([
            $note=Suspicious_Beacon,
            $msg=fmt("Potential C2 beacon: %s %s", method, unescaped_URI),
            $conn=c,
            $identifier=cat(c$id$orig_h, c$id$resp_h)
        ]);
    }
}
