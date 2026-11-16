// Apache-2.0. Dedicated unsandboxed macOS file-keychain helper.
// No enumeration, update, delete, iCloud/DPK fallback or ACL changes.
import Foundation
import Security
import Darwin

func stop(_ code: Int32) -> Never { exit(code) }
func statusCode(_ status: OSStatus) -> Int32 {
    if status == errSecItemNotFound { return 21 }
    if status == errSecInteractionNotAllowed || status == errSecUserCanceled || status == errSecAuthFailed { return 22 }
    return 23
}

guard CommandLine.arguments.count == 1, isatty(STDIN_FILENO) == 0, isatty(STDOUT_FILENO) == 0, geteuid() != 0 else { stop(20) }
let input = FileHandle.standardInput.readData(ofLength: 4097)
guard input.count <= 4096,
      let object = try? JSONSerialization.jsonObject(with: input),
      let request = object as? [String: Any],
      Set(request.keys) == Set(["version", "operation", "installationId"]),
      let version = request["version"] as? NSNumber, CFGetTypeID(version) != CFBooleanGetTypeID(), version.intValue == 1,
      let operation = request["operation"] as? String, ["read", "create"].contains(operation),
      let installation = request["installationId"] as? String,
      installation.range(of: "^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$", options: .regularExpression) != nil
else { stop(20) }

// The user-context default file keychain is selected once, explicitly reused
// for add and lookup. No full search list or other user's keychain is queried.
var selected: SecKeychain?
let selectedStatus = SecKeychainCopyDefault(&selected)
guard selectedStatus == errSecSuccess, let keychain = selected else { stop(statusCode(selectedStatus)) }
let service = "ai.nuluno.access.vault." + installation
let account = "local-owner"

func readMaster() -> (OSStatus, Data?) {
    let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccount: account,
        kSecMatchSearchList: [keychain],
        kSecMatchLimit: kSecMatchLimitOne,
        kSecReturnData: true,
        kSecUseAuthenticationUI: kSecUseAuthenticationUIFail
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    return (status, result as? Data)
}

var (status, value) = readMaster()
if operation == "create" && status == errSecItemNotFound {
    var random = Data(count: 32)
    let randomStatus = random.withUnsafeMutableBytes { buffer in
        SecRandomCopyBytes(kSecRandomDefault, 32, buffer.baseAddress!)
    }
    guard randomStatus == errSecSuccess else { stop(23) }
    // Omitting kSecAttrAccess retains Apple's default creator-only ACL. There
    // is no empty/all-app trusted list, no ACL mutation or broad key sharing.
    // Legacy file keychains do not receive DPK-only ThisDeviceOnly flags.
    let attributes: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccount: account,
        kSecAttrLabel: "Nuluno Access local vault",
        kSecUseKeychain: keychain,
        kSecUseAuthenticationUI: kSecUseAuthenticationUIFail,
        kSecValueData: random
    ]
    let added = SecItemAdd(attributes as CFDictionary, nil)
    if added == errSecSuccess {
        status = errSecSuccess; value = random
    } else if added == errSecDuplicateItem {
        (status, value) = readMaster()
    } else { random.resetBytes(in: 0..<random.count); stop(statusCode(added)) }
    random.resetBytes(in: 0..<random.count)
}
guard status == errSecSuccess else { stop(statusCode(status)) }
guard var master = value, master.count == 32 else { stop(24) }
// Binary stdout is consumed only by the parent Node private pipe. No secret
// goes to arguments, environment, logs, a browser or an agent-facing API.
FileHandle.standardOutput.write(master)
master.resetBytes(in: 0..<master.count)
stop(0)
