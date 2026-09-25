# PlatformIO pre-script: turns WIFI_SSID, WIFI_PASSWORD, OPENAI_API_KEY, OPENAI_VOICE and VOLUME into
# build defines, from the environment or the gitignored .env file at the project root.
import hashlib
import os
Import("env")

values = {}
path = os.path.join(env.subst("$PROJECT_DIR"), ".env")
if os.path.isfile(path):
    with open(path, encoding="utf-8") as lines:
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key.strip()] = value
values.update({k: os.environ[k] for k in ("WIFI_SSID", "WIFI_PASSWORD", "OPENAI_API_KEY", "OPENAI_VOICE", "VOLUME") if os.environ.get(k)})

defines = []
if values.get("WIFI_SSID"):
    defines += [("WEBRTC_WIFI_SSID", values["WIFI_SSID"]), ("WEBRTC_WIFI_PASSWORD", values.get("WIFI_PASSWORD", ""))]
for key in ("OPENAI_API_KEY", "OPENAI_VOICE"):
    if values.get(key):
        defines.append((key, values[key]))

# Values go in a force-included header in the build directory, so no shell quoting applies.
def c_string(value):
    out = ""
    for byte in value.encode("utf-8"):
        char = chr(byte)
        out += "\\" + char if char in "\\\"" else char if 32 <= byte < 127 and char != "?" else "\\%03o" % byte
    return '"' + out + '"'

header = "".join("#define %s %s\n" % (name, c_string(value)) for name, value in defines)
if values.get("VOLUME"):
    if not values["VOLUME"].isdigit() or int(values["VOLUME"]) > 100:
        raise SystemExit("VOLUME must be 0..100")
    header += "#define WEBRTC_VOLUME %d\n" % int(values["VOLUME"])
if header:
    target = os.path.join(env.subst("$BUILD_DIR"), "webrtc_secrets.h")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    if not os.path.isfile(target) or open(target, encoding="utf-8").read() != header:
        with open(target, "w", encoding="utf-8") as out:
            out.write(header)
    # The hash define forces a rebuild when a value changes.
    env.Append(CCFLAGS=["-include", target], CPPDEFINES=[("WEBRTC_SECRETS_HASH", hashlib.sha1(header.encode()).hexdigest()[:8])])
