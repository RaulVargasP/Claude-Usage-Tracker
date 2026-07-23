import Foundation

/// Bridge to the `cux` account switcher's credential store.
///
/// `cux` (github.com/inulute/cux) keeps one keychain entry per managed account
/// under service "cux-backup" (account "account-<slot>-<email>", value
/// "go-keyring-base64:" + base64(JSON blob)), re-reads that entry before every
/// token refresh, and preserves unknown fields when rewriting it. That makes the
/// entry a safe single source of truth for an account's OAuth token lineage:
///
///  - SOURCING tokens from it means we start from the newest lineage instead of
///    a possibly-stale private snapshot, whose refresh would fail with
///    invalid_grant — or worse, trip refresh-token-reuse detection and revoke
///    the whole token family, killing the account until a manual re-login.
///  - WRITING rotated tokens back means cux's next refresh adopts our lineage
///    instead of consuming a dead token.
///
/// Everything here degrades to a no-op when cux is not installed (`~/.cux`
/// absent), so profiles not managed by cux keep the legacy behavior.
final class CuxBridge {
    static let shared = CuxBridge()

    struct Slot {
        let number: Int
        let email: String
        var keychainAccount: String { "account-\(number)-\(email)" }
    }

    private static let service = "cux-backup"
    private static let valuePrefix = "go-keyring-base64:"
    private let accountsDir = (NSHomeDirectory() as NSString)
        .appendingPathComponent(".cux/accounts")

    /// Finds the cux slot managing `email` by scanning `~/.cux/accounts/<NN>-<email>/`.
    /// Returns nil when cux is absent or does not manage this account.
    func slot(forEmail email: String?) -> Slot? {
        guard let email = email?.lowercased(), !email.isEmpty,
              let entries = try? FileManager.default.contentsOfDirectory(atPath: accountsDir) else {
            return nil
        }
        for entry in entries {
            guard let dash = entry.firstIndex(of: "-"),
                  let number = Int(entry[entry.startIndex..<dash]) else { continue }
            let slotEmail = String(entry[entry.index(after: dash)...])
            if slotEmail.lowercased() == email {
                return Slot(number: number, email: slotEmail)
            }
        }
        return nil
    }

    /// Convenience: extracts `emailAddress` from a profile's `oauthAccountJSON`
    /// (the raw `oauthAccount` object from `.claude.json`) and maps it to a slot.
    func slot(forOAuthAccountJSON json: String?) -> Slot? {
        guard let json = json, let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let email = obj["emailAddress"] as? String else {
            return nil
        }
        return slot(forEmail: email)
    }

    // MARK: - Account roster

    struct ManagedAccount {
        let slot: Int
        let email: String
        let alias: String?
        let accountUuid: String?
        /// Raw JSON of the account's oauth block (`~/.cux/accounts/<slot>-<email>/oauth.json`),
        /// the same shape `.claude.json` stores under `oauthAccount`.
        let oauthAccountJSON: String?
    }

    /// The roster of accounts cux manages, per `~/.cux/state.json` (slot, email,
    /// alias, account uuid) joined with each slot's `oauth.json`. Empty when cux
    /// is absent — callers treat that as "no roster to mirror".
    func managedAccounts() -> [ManagedAccount] {
        let statePath = (NSHomeDirectory() as NSString).appendingPathComponent(".cux/state.json")
        guard let data = FileManager.default.contents(atPath: statePath),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let accounts = root["accounts"] as? [String: [String: Any]] else {
            return []
        }
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: accountsDir)) ?? []
        var result: [ManagedAccount] = []
        for (_, a) in accounts {
            guard let slot = a["slot"] as? Int, let email = a["email"] as? String else { continue }
            var oauthJSON: String? = nil
            if let entry = entries.first(where: { $0.hasSuffix("-\(email)") }) {
                let path = (accountsDir as NSString).appendingPathComponent("\(entry)/oauth.json")
                if let d = FileManager.default.contents(atPath: path) {
                    oauthJSON = String(data: d, encoding: .utf8)
                }
            }
            result.append(ManagedAccount(slot: slot, email: email,
                                         alias: a["alias"] as? String,
                                         accountUuid: a["uuid"] as? String,
                                         oauthAccountJSON: oauthJSON))
        }
        return result.sorted { $0.slot < $1.slot }
    }

    /// Reads the full credential blob JSON (`{"claudeAiOauth": {...}, ...}`) from
    /// the slot's backup entry. Read-only; never rotates or mutates anything.
    func readCredentials(_ slot: Slot) -> String? {
        guard let result = runSecurity([
            "find-generic-password", "-s", Self.service, "-a", slot.keychainAccount, "-w"
        ]), result.exitCode == 0 else {
            return nil
        }
        let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return nil }
        guard value.hasPrefix(Self.valuePrefix) else {
            // Defensive: accept a raw-JSON payload should cux ever drop the prefix.
            return value.hasPrefix("{") ? value : nil
        }
        guard let data = Data(base64Encoded: String(value.dropFirst(Self.valuePrefix.count))),
              let json = String(data: data, encoding: .utf8) else {
            return nil
        }
        return json
    }

    /// Writes a rotated credential blob back into the slot's backup entry so cux's
    /// next refresh starts from this lineage. Top-level fields present in the
    /// current entry but missing from `json` (e.g. `mcpOAuth`) are preserved.
    func writeCredentials(_ json: String, to slot: Slot) {
        var outJSON = json
        if let currentJSON = readCredentials(slot),
           let currentData = currentJSON.data(using: .utf8),
           var root = try? JSONSerialization.jsonObject(with: currentData) as? [String: Any],
           let newData = json.data(using: .utf8),
           let newRoot = try? JSONSerialization.jsonObject(with: newData) as? [String: Any] {
            for (key, value) in newRoot { root[key] = value }
            // Single-line output: the payload round-trips through
            // `security add-generic-password -w` (see mergeRefreshedCredentials).
            if let merged = try? JSONSerialization.data(withJSONObject: root, options: [.sortedKeys]),
               let mergedString = String(data: merged, encoding: .utf8) {
                outJSON = mergedString
            }
        }
        guard let payload = outJSON.data(using: .utf8) else { return }
        let value = Self.valuePrefix + payload.base64EncodedString()
        let result = runSecurity([
            "add-generic-password", "-s", Self.service, "-a", slot.keychainAccount, "-w", value, "-U"
        ])
        if let result = result, result.exitCode == 0 {
            LoggingService.shared.log("CuxBridge: wrote rotated lineage back to cux-backup slot \(slot.number) (\(slot.email))")
        } else {
            LoggingService.shared.log("CuxBridge: write-back to cux-backup slot \(slot.number) failed (exit=\(result?.exitCode ?? -1)) — cux may refresh with a consumed token")
        }
    }

    // MARK: - security CLI

    private struct SecurityResult {
        let exitCode: Int32
        let stdout: String
    }

    /// Runs `/usr/bin/security` with a bounded wait so a hung keychain daemon
    /// can never block the caller forever. Payloads are tiny (<2 KB), so reading
    /// stdout after exit cannot deadlock on a full pipe.
    private func runSecurity(_ arguments: [String]) -> SecurityResult? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        process.arguments = arguments
        let out = Pipe()
        process.standardOutput = out
        process.standardError = Pipe()
        do { try process.run() } catch { return nil }
        let deadline = Date().addingTimeInterval(10)
        while process.isRunning && Date() < deadline {
            usleep(50_000)
        }
        if process.isRunning {
            process.terminate()
            return nil
        }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        return SecurityResult(exitCode: process.terminationStatus,
                              stdout: String(data: data, encoding: .utf8) ?? "")
    }
}
