import XCTest
@testable import Klav

/// The vault's type tabs and «Codes» (VaultFilter.swift), as the
/// extension's test/filters.test.ts.
final class VaultFilterTests: XCTestCase {
    private var next = 0

    private func item(_ kind: Kind, _ title: String? = nil) -> ItemInfo {
        next += 1
        let title = title ?? "\(kind) \(next)"
        return ItemInfo(id: "id-\(next)", reference: "", vaultId: "v", vault: "Personal", projectId: "p",
                        project: "General", kind: kind, title: title, username: nil, urls: [], tags: [],
                        version: 1, updatedAt: 0, trashed: false)
    }

    private lazy var vault: [ItemInfo] = [
        item(.login), item(.login), item(.login), item(.card), item(.note), item(.totp), item(.sshKey),
    ]

    func testTabsCountEachTypeInAFixedOrderAndLeaveOutTheEmptyOnes() {
        XCTAssertEqual(VaultFilter.tabs(vault, codes: 2, chosen: .all), [
            .init(filter: .all, count: 7),
            .init(filter: .login, count: 3),
            .init(filter: .codes, count: 2),
            .init(filter: .card, count: 1),
            .init(filter: .note, count: 1),
            .init(filter: .sshKey, count: 1),
        ])
    }

    func testCodesWaitsForItsCountAndHidesWithNone() {
        XCTAssertFalse(VaultFilter.tabs(vault, codes: nil, chosen: .all).contains { $0.filter == .codes })
        XCTAssertFalse(VaultFilter.tabs(vault, codes: 0, chosen: .all).contains { $0.filter == .codes })
        XCTAssertEqual(VaultFilter.tabs(vault, codes: nil, chosen: .codes).first { $0.filter == .codes },
                       .init(filter: .codes, count: nil))
    }

    func testTheChosenTabStaysWhenASearchEmptiesIt() {
        XCTAssertEqual(VaultFilter.tabs([item(.login)], codes: 0, chosen: .card), [
            .init(filter: .all, count: 1), .init(filter: .login, count: 1), .init(filter: .card, count: 0),
        ])
    }

    func testOneTypeWithoutCodesNeedsNoTabs() {
        XCTAssertEqual(VaultFilter.tabs([item(.login), item(.login)], codes: 0, chosen: .all), [])
        XCTAssertEqual(VaultFilter.tabs([], codes: nil, chosen: .all), [])
        XCTAssertEqual(VaultFilter.tabs([item(.login), item(.note)], codes: 0, chosen: .all).count, 3)
    }

    func testStandaloneCodesAreCodes() {
        let tabs = VaultFilter.tabs([item(.totp), item(.totp), item(.login)], codes: 2, chosen: .all)
        XCTAssertEqual(tabs.map(\.filter), [.all, .login, .codes])
    }

    func testFilteredKeepsOneTypeOrTheItemsWithACode() {
        XCTAssertEqual(VaultFilter.login.filtered(vault, codeIds: nil).count, 3)
        XCTAssertEqual(VaultFilter.apiKey.filtered(vault, codeIds: nil).count, 0)
        XCTAssertEqual(VaultFilter.all.filtered(vault, codeIds: nil).count, 7)
        // «Codes» goes by the code, not the type; nothing until klav-core said.
        let withCodes: Set<String> = [vault[0].id, vault[5].id]
        XCTAssertEqual(VaultFilter.codes.filtered(vault, codeIds: withCodes).map(\.id), [vault[0].id, vault[5].id])
        XCTAssertEqual(VaultFilter.codes.filtered(vault, codeIds: nil).count, 0)
    }

    func testEveryTabHasAName() {
        for filter in VaultFilter.allCases {
            XCTAssertFalse(filter.label.isEmpty)
            XCTAssertFalse(filter.label.hasPrefix("filter."), "\(filter) has no English text")
        }
        XCTAssertEqual(VaultFilter.codes.label, "Codes")
    }
}
