import Darwin
import os

/// Memory the extension uses (`phys_footprint`, what iOS's limit counts),
/// logged at each step so the limit can be checked (ADR 0018 §4).
enum Footprint {
    static let log = Logger(subsystem: "dev.klav.ios", category: "autofill")

    /// Megabytes, or -1 if unknown. A Swift shim over `task_info`.
    static func megabytes() -> Double {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        guard result == KERN_SUCCESS else { return -1 }
        return Double(info.phys_footprint) / 1_048_576
    }

    static func note(_ step: String) {
        let mb = megabytes()
        log.info("footprint \(step, privacy: .public): \(mb, format: .fixed(precision: 1), privacy: .public) MiB")
    }
}
