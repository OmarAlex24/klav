import XCTest
@testable import Klav

/// ADR 0025: the site the AutoFill sheet leaves for the app to add, and the
/// relation klav-core gives it.
final class SiteOfferTests: XCTestCase {
    private var defaults: UserDefaults!
    private var suite: String!

    override func setUp() {
        suite = "klav-site-offer-\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)
    }

    override func tearDown() {
        defaults.removePersistentDomain(forName: suite)
    }

    func testTheLastOfferIsKeptUntilClearedOrOld() {
        XCTAssertNil(SiteOffer.pending(in: defaults))
        let now = Date()
        let first = SiteOffer(itemId: "a", title: "Zeta", host: "1password.com", savedFor: "my.1password.com", at: now)
        let second = SiteOffer(itemId: "b", title: "Beta", host: "example.com", savedFor: "id.example.com", at: now)
        SiteOffer.leave(first, in: defaults)
        SiteOffer.leave(second, in: defaults)
        XCTAssertEqual(SiteOffer.pending(in: defaults, now: now), second)
        // An old offer is dropped unasked.
        XCTAssertNil(SiteOffer.pending(in: defaults, now: now.addingTimeInterval(SiteOffer.lifetime + 1)))
        XCTAssertNil(SiteOffer.pending(in: defaults, now: now))
        SiteOffer.leave(first, in: defaults)
        SiteOffer.clear(in: defaults)
        XCTAssertNil(SiteOffer.pending(in: defaults))
    }

    func testTheRelationComesFromKlavCore() {
        let saved = ["https://my.1password.com/signin"]
        XCTAssertEqual(siteRelation(host: "my.1password.com", urls: saved), .exact)
        XCTAssertEqual(siteRelation(host: "a.my.1password.com", urls: saved), .subdomain)
        XCTAssertEqual(siteRelation(host: "1password.com", urls: saved), .parent)
        XCTAssertNil(siteRelation(host: "com", urls: saved))
        XCTAssertNil(siteRelation(host: "start.1password.com", urls: saved))
    }
}
