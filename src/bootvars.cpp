#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <cwchar>
#include <string>
#include <vector>
#include <algorithm>

static const wchar_t* kGlobal = L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";
static const wchar_t* kSecDb = L"{d719b2cb-3d3a-4596-a3bc-dad00e67656f}";

static uint16_t rd16(const uint8_t* p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t* p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static void wr16(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}

static void wr32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static std::string guid_str(const uint8_t* p) {
    char b[64];
    snprintf(b, sizeof b,
             "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             rd32(p), rd16(p + 4), rd16(p + 6),
             p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    return b;
}

static void hexdump(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; i += 16) {
        printf("  %04zX  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < n) printf("%02X ", p[i + j]);
            else printf("   ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < n; j++) {
            uint8_t c = p[i + j];
            putchar(c >= 0x20 && c < 0x7f ? c : '.');
        }
        printf("|\n");
    }
}

static void var_attrs(DWORD a) {
    struct { DWORD b; const char* n; } f[] = {
        { 0x00000001, "NV" }, { 0x00000002, "BS" }, { 0x00000004, "RT" },
        { 0x00000008, "HWERR" }, { 0x00000010, "AUTH" },
        { 0x00000020, "TIME_AUTH" }, { 0x00000040, "APPEND" }
    };
    printf(" [");
    for (auto& e : f)
        if (a & e.b) printf("%s ", e.n);
    printf("]");
}

struct Var {
    std::vector<uint8_t> b;
    DWORD attrs = 0;
    DWORD err = 0;
    bool ok = false;
};

static Var read_var(const wchar_t* name, const wchar_t* guid) {
    Var v;
    DWORD attrs = 0;
    std::vector<uint8_t> tmp(512);
    for (int attempt = 0; attempt < 12; attempt++) {
        SetLastError(0);
        DWORD got = GetFirmwareEnvironmentVariableExW(
            name, guid, tmp.data(), (DWORD)tmp.size(), &attrs);
        DWORD e = GetLastError();
        if (got != 0 && got <= tmp.size()) {
            v.b.assign(tmp.begin(), tmp.begin() + got);
            v.attrs = attrs;
            v.ok = true;
            return v;
        }
        if (got > tmp.size()) {
            tmp.resize(got);
            continue;
        }
        if (e == ERROR_SUCCESS) {
            v.attrs = attrs;
            v.ok = true;
            return v;
        }
        if (e == ERROR_INSUFFICIENT_BUFFER || e == ERROR_MORE_DATA) {
            tmp.resize(tmp.size() * 2);
            continue;
        }
        v.err = e;
        return v;
    }
    v.err = ERROR_INSUFFICIENT_BUFFER;
    return v;
}

struct Node {
    uint8_t type = 0, subtype = 0;
    uint16_t len = 0;
    std::string text;
};

static std::string dp_text(const uint8_t* p, uint16_t len, uint8_t type, uint8_t sub) {
    char b[320];
    switch (type) {
    case 0x01:
        if (sub == 0x01 && len >= 6)
            snprintf(b, sizeof b, "Pci(dev 0x%02X, fn 0x%02X)", p[5], p[4]);
        else snprintf(b, sizeof b, "Hardware(%02X)", sub);
        break;
    case 0x02:
        if (len >= 12)
            snprintf(b, sizeof b, "Acpi(HID 0x%08X, UID 0x%08X)", rd32(p + 4), rd32(p + 8));
        else snprintf(b, sizeof b, "Acpi(%02X)", sub);
        break;
    case 0x03:
        snprintf(b, sizeof b, "Msg(%02X)", sub);
        break;
    case 0x04:
        if (sub == 0x01 && len >= 42) {
            uint32_t pn = rd32(p + 4);
            uint64_t start = rd64(p + 8), size = rd64(p + 16);
            uint8_t mbr = p[40], sig = p[41];
            std::string g = sig == 1 ? guid_str(p + 24) : "-";
            snprintf(b, sizeof b,
                     "HD(part %u, start 0x%llX, size 0x%llX, mbr %u, sig %u, %s)",
                     pn, (unsigned long long)start, (unsigned long long)size,
                     mbr, sig, g.c_str());
        } else if (sub == 0x04 && len >= 6) {
            std::wstring w;
            for (uint16_t i = 4; i + 2 <= len; i += 2) {
                uint16_t c = rd16(p + i);
                if (!c) break;
                w.push_back((wchar_t)c);
            }
            snprintf(b, sizeof b, "File(%ls)", w.c_str());
        } else if (sub == 0x02) {
            snprintf(b, sizeof b, "CDROM");
        } else {
            snprintf(b, sizeof b, "Media(%02X)", sub);
        }
        break;
    case 0x05:
        snprintf(b, sizeof b, "BBS(%02X)", sub);
        break;
    case 0x7F:
        snprintf(b, sizeof b, sub == 0xFF ? "End" : "EndInstance");
        break;
    default:
        snprintf(b, sizeof b, "Type%02X(%02X)", type, sub);
        break;
    }
    return b;
}

struct LoadOption {
    uint32_t attrs = 0;
    uint16_t path_len = 0;
    std::wstring desc;
    std::vector<Node> nodes;
    std::vector<uint8_t> optional;
    bool ok = false;
};

static LoadOption parse_option(const uint8_t* p, size_t n) {
    LoadOption o;
    if (n < 6) return o;
    o.attrs = rd32(p);
    o.path_len = rd16(p + 4);
    size_t off = 6;
    while (off + 2 <= n) {
        uint16_t c = rd16(p + off);
        off += 2;
        if (!c) break;
        o.desc.push_back((wchar_t)c);
    }
    size_t begin = off;
    size_t end = std::min<size_t>(begin + o.path_len, n);
    while (off + 4 <= end) {
        Node nd;
        nd.type = p[off];
        nd.subtype = p[off + 1];
        nd.len = rd16(p + off + 2);
        if (nd.len < 4 || off + nd.len > end) break;
        nd.text = dp_text(p + off, nd.len, nd.type, nd.subtype);
        o.nodes.push_back(nd);
        off += nd.len;
        if (nd.type == 0x7F && nd.subtype == 0xFF) break;
    }
    if (end <= n) o.optional.assign(p + end, p + n);
    o.ok = true;
    return o;
}

static void print_option(const LoadOption& o, const wchar_t* tag) {
    printf("%ls  attrs 0x%08X [", tag, o.attrs);
    if (o.attrs & 0x1) printf("ACTIVE ");
    if (o.attrs & 0x2) printf("FORCE_RECONNECT ");
    if (o.attrs & 0x8) printf("HIDDEN ");
    if (o.attrs & 0x100) printf("CATEGORY_BOOT ");
    if (o.attrs & 0x200) printf("CATEGORY_APP ");
    printf("]\n");
    printf("  desc      %ls\n", o.desc.c_str());
    printf("  pathlen   %u\n", o.path_len);
    for (size_t i = 0; i < o.nodes.size(); i++)
        printf("  [%zu]      %s (type %02X sub %02X len %u)\n",
               i, o.nodes[i].text.c_str(), o.nodes[i].type,
               o.nodes[i].subtype, o.nodes[i].len);
    printf("  optional  %zu bytes\n", o.optional.size());
    if (!o.optional.empty()) hexdump(o.optional.data(), o.optional.size());
}

static void print_u16(const wchar_t* name, const wchar_t* guid) {
    Var v = read_var(name, guid);
    if (!v.ok) {
        printf("  %-14ls <0x%08lX>\n", name, v.err);
        return;
    }
    printf("  %-14ls ", name);
    if (v.b.size() >= 2) printf("0x%04X", rd16(v.b.data()));
    else printf("<empty>");
    var_attrs(v.attrs);
    printf("\n");
}

static void print_var_hex(const wchar_t* name, const wchar_t* guid) {
    Var v = read_var(name, guid);
    if (!v.ok) {
        printf("  %-14ls <0x%08lX>\n", name, v.err);
        return;
    }
    printf("%ls  %zu bytes", name, v.b.size());
    var_attrs(v.attrs);
    printf("\n");
    hexdump(v.b.data(), v.b.size());
}

static bool enable_privilege(const wchar_t* name) {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return false;
    TOKEN_PRIVILEGES tp{};
    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        SetLastError(0);
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof tp, nullptr, nullptr);
        ok = GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(tok);
    return ok;
}

static std::vector<uint8_t> make_fixture() {
    const wchar_t* desc = L"Windows Boot Manager";
    const wchar_t* file = L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
    std::vector<uint8_t> hd(42, 0);
    hd[0] = 0x04; hd[1] = 0x01;
    wr16(hd.data() + 2, 42);
    wr32(hd.data() + 4, 1);
    wr16(hd.data() + 8 + 0, 0x0800);
    hd[40] = 0x02; hd[41] = 0x01;
    uint8_t guid[16] = { 0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
                         0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B };
    for (int i = 0; i < 16; i++) hd[24 + i] = guid[i];

    size_t flen = 4 + (wcslen(file) + 1) * 2;
    std::vector<uint8_t> fp(flen, 0);
    fp[0] = 0x04; fp[1] = 0x04;
    wr16(fp.data() + 2, (uint16_t)flen);
    for (size_t i = 0; i <= wcslen(file); i++) wr16(fp.data() + 4 + i * 2, (uint16_t)file[i]);

    std::vector<uint8_t> end = { 0x7F, 0xFF, 0x04, 0x00 };
    std::vector<uint8_t> path;
    path.insert(path.end(), hd.begin(), hd.end());
    path.insert(path.end(), fp.begin(), fp.end());
    path.insert(path.end(), end.begin(), end.end());

    std::vector<uint8_t> out(6, 0);
    wr32(out.data(), 0x00000001);
    wr16(out.data() + 4, (uint16_t)path.size());
    for (size_t i = 0; i <= wcslen(desc); i++) {
        uint16_t c = (uint16_t)desc[i];
        out.push_back((uint8_t)c);
        out.push_back((uint8_t)(c >> 8));
    }
    out.insert(out.end(), path.begin(), path.end());
    const char* opt = "WINDOWS";
    for (size_t i = 0; i < 8; i++) out.push_back((uint8_t)opt[i]);
    return out;
}

static int selftest() {
    auto b = make_fixture();
    LoadOption o = parse_option(b.data(), b.size());
    int bad = 0;
    auto ck = [&](bool c, const char* what) {
        printf("  %s  %s\n", c ? "ok  " : "BAD ", what);
        if (!c) bad++;
    };
    printf("selftest: synthetic EFI_LOAD_OPTION (%zu bytes)\n", b.size());
    ck(o.ok, "parsed");
    ck(o.attrs == 1, "attributes == ACTIVE");
    ck(o.desc == L"Windows Boot Manager", "description");
    ck(o.path_len == 42 + 4 + (wcslen(L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi") + 1) * 2 + 4,
       "file path list length");
    ck(o.nodes.size() == 3, "three device path nodes");
    ck(o.nodes.size() == 3 && o.nodes[0].type == 0x04 && o.nodes[0].subtype == 0x01,
       "first node is HD()");
    ck(o.nodes.size() == 3 && o.nodes[1].subtype == 0x04, "second node is File()");
    ck(o.nodes.size() == 3 && o.nodes[2].type == 0x7F, "last node is End");
    ck(o.optional.size() == 8, "optional data");
    printf("  %s\n", bad ? "FAILED" : "PASS");
    return bad ? 1 : 0;
}

static int offline(const wchar_t* path) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        printf("cannot open %ls (0x%08lX)\n", path, GetLastError());
        return 1;
    }
    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    std::vector<uint8_t> b((size_t)sz.QuadPart);
    DWORD got = 0;
    ReadFile(h, b.data(), (DWORD)b.size(), &got, nullptr);
    CloseHandle(h);
    b.resize(got);
    printf("%ls  %zu bytes\n\n", path, b.size());
    LoadOption o = parse_option(b.data(), b.size());
    if (!o.ok) {
        printf("not an EFI_LOAD_OPTION\n");
        return 1;
    }
    print_option(o, L"load option");
    printf("\nraw\n");
    hexdump(b.data(), b.size());
    return 0;
}

static void dump_firmware(const wchar_t* guid) {
    printf("firmware variables  guid %ls\n", guid);
    print_u16(L"BootCurrent", guid);
    print_u16(L"BootNext", guid);
    print_u16(L"Timeout", guid);
    print_u16(L"BootOrder", guid);
    printf("\n");

    Var order = read_var(L"BootOrder", guid);
    if (order.ok) {
        printf("BootOrder  %zu entries\n", order.b.size() / 2);
        for (size_t i = 0; i + 2 <= order.b.size(); i += 2) {
            uint16_t n = rd16(order.b.data() + i);
            wchar_t name[16];
            swprintf(name, 16, L"Boot%04X", n);
            Var v = read_var(name, guid);
            if (!v.ok) continue;
            LoadOption o = parse_option(v.b.data(), v.b.size());
            if (!o.ok) continue;
            printf("\n");
            print_option(o, name);
        }
    } else {
        printf("BootOrder unavailable (0x%08lX)\n", order.err);
    }

    printf("\nsecure boot\n");
    print_u16(L"SecureBoot", guid);
    print_u16(L"SetupMode", guid);
    print_var_hex(L"PK", kSecDb);
    print_var_hex(L"KEK", kSecDb);
    print_var_hex(L"db", kSecDb);
}

int wmain(int argc, wchar_t** argv) {
    bool have_priv = enable_privilege(SE_SYSTEM_ENVIRONMENT_NAME);
    const wchar_t* guid = kGlobal;
    const wchar_t* only = nullptr;
    const wchar_t* offline_path = nullptr;
    const wchar_t* emit_path = nullptr;
    bool raw = false;

    for (int i = 1; i < argc; i++) {
        if (!wcscmp(argv[i], L"--selftest")) return selftest();
        else if (!wcscmp(argv[i], L"--emit") && i + 1 < argc) emit_path = argv[++i];
        else if (!wcscmp(argv[i], L"--offline") && i + 1 < argc) offline_path = argv[++i];
        else if (!wcscmp(argv[i], L"--var") && i + 1 < argc) only = argv[++i];
        else if (!wcscmp(argv[i], L"--guid") && i + 1 < argc) guid = argv[++i];
        else if (!wcscmp(argv[i], L"--raw")) raw = true;
        else {
            printf("bootvars [--offline file] [--var name] [--guid guid] [--raw] [--selftest] [--emit file]\n");
            return 2;
        }
    }

    if (emit_path) {
        auto b = make_fixture();
        HANDLE h = CreateFileW(emit_path, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return 1;
        DWORD put = 0;
        WriteFile(h, b.data(), (DWORD)b.size(), &put, nullptr);
        CloseHandle(h);
        printf("%ls  %zu bytes\n", emit_path, b.size());
        return 0;
    }

    if (offline_path) return offline(offline_path);

    if (only) {
        if (raw) { print_var_hex(only, guid); return 0; }
        Var v = read_var(only, guid);
        if (!v.ok) {
            printf("%ls unavailable (0x%08lX)\n", only, v.err);
            return 1;
        }
        LoadOption o = parse_option(v.b.data(), v.b.size());
        if (o.ok) print_option(o, only);
        else print_var_hex(only, guid);
        return 0;
    }

    printf("privilege SeSystemEnvironmentPrivilege: %s\n",
           have_priv ? "enabled" : "not held");
    printf("note: needs uefi firmware + elevated process. --offline works without either.\n\n");
    dump_firmware(guid);
    return 0;
}
